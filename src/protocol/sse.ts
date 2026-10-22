import { id, object, parseEvent, parseJson, string, ValidationError } from './wire.js';
import type { ConversationEvent } from './wire.js';

export type StreamFrame = { kind: 'event'; event: ConversationEvent } | { kind: 'delta'; messageId: string; text: string };
/** One bounded frame at a time. The caller controls reads by advancing the iterator. */
export async function* parseEventStream(body: ReadableStream<Uint8Array>, options: { maxFrameBytes?: number; maxStreamBytes?: number; signal?: AbortSignal } = {}): AsyncGenerator<StreamFrame> {
  const maxFrame = options.maxFrameBytes ?? 1048576, maxStream = options.maxStreamBytes ?? 16777216;
  if (![maxFrame,maxStream].every(value => Number.isSafeInteger(value) && value > 0)) throw new TypeError('Invalid stream budget');
  const reader = body.getReader(), decoder = new TextDecoder('utf-8',{fatal:true});
  let buffer = '', bytes = 0, frameBytes = 0, data: string[] = [], eventType = '', eventId: string | undefined;
  const abort = () => { void reader.cancel(options.signal?.reason); };
  options.signal?.addEventListener('abort',abort,{once:true});
  function frame(): StreamFrame | undefined {
    if (!data.length) return;
    const value = parseJson(data.join('\n'));
    if (eventType === 'text-delta') {
      if (eventId !== undefined) throw new ValidationError('sse.delta.id');
      const delta=object(value); return {kind:'delta',messageId:id(delta.message_id,'message_id'),text:string(delta.text,'text',false)};
    }
    const event=parseEvent(value);
    if (eventId !== event.id) throw new ValidationError('sse.id');
    return {kind:'event',event};
  }
  try {
    for (;;) {
      options.signal?.throwIfAborted();
      const item = await reader.read(); options.signal?.throwIfAborted();
      if (item.done) { decoder.decode(); break; } // An unterminated frame is incomplete and discarded.
      bytes += item.value.byteLength; if (bytes > maxStream) throw new ValidationError('sse.stream.size');
      buffer += decoder.decode(item.value,{stream:true});
      for (;;) {
        const end=buffer.search(/[\r\n]/); if (end<0) break;
        if (buffer[end]==='\r' && end===buffer.length-1) break;
        const line=buffer.slice(0,end), width=buffer[end]==='\r' && buffer[end+1]==='\n'?2:1;
        buffer=buffer.slice(end+width); frameBytes+=Buffer.byteLength(line)+width;
        if(frameBytes>maxFrame) throw new ValidationError('sse.frame.size');
        if (!line) {
          const result=frame(); data=[];eventType='';eventId=undefined;frameBytes=0;
          if(result) yield result;
        } else if (!line.startsWith(':')) {
          const colon=line.indexOf(':'),field=colon<0?line:line.slice(0,colon);let value=colon<0?'':line.slice(colon+1);if(value.startsWith(' '))value=value.slice(1);
          if(field==='data')data.push(value); else if(field==='event')eventType=value; else if(field==='id'){if(value.includes('\0'))throw new ValidationError('sse.id');eventId=value;}
        }
      }
      if(frameBytes+Buffer.byteLength(buffer)>maxFrame)throw new ValidationError('sse.frame.size');
    }
  } finally { options.signal?.removeEventListener('abort',abort); await reader.cancel().catch(()=>{});reader.releaseLock(); }
}
