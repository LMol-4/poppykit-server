import { object, string, ValidationError } from '../protocol/wire.js';
import { secureUrl } from './transport.js';
import type { PoppyDocument } from './discovery.js';

export type AlternativeReference = { type: 'web'; url: string } | { type: 'openapi'; url: string; operation_id: string } | { type: 'mcp'; url: string; tool: string };
export interface Alternative { instructions?: string; references?: AlternativeReference[] }
export interface ExcludedTask { task: string; alternative?: Alternative }
function text(value: unknown, field: string, max: number): string {
  const result = string(value, field);
  if ([...result].length > max) throw new ValidationError(field);
  return result;
}
export function parseAlternative(value: unknown, document: PoppyDocument): Alternative {
  const item = object(value, 'alternative'), result: Alternative = {};
  if (!('instructions' in item) && !('references' in item)) throw new ValidationError('alternative');
  if ('instructions' in item) result.instructions = text(item.instructions, 'instructions', 2000);
  if ('references' in item) {
    if (!Array.isArray(item.references)) throw new ValidationError('references');
    result.references = [];
    for (const reference of item.references) {
      const ref = object(reference, 'reference'), type = string(ref.type, 'reference.type');
      if (!['web', 'openapi', 'mcp'].includes(type)) continue;
      const url = string(ref.url, 'reference.url');
      if (type !== 'web' && !document.apis?.some(api => api.type === type && api.url === url)) continue;
      secureUrl(url);
      if (type === 'web') result.references.push({ type, url });
      else {
        const field = type === 'openapi' ? 'operation_id' : 'tool', name = string(ref[field], field);
        result.references.push(type === 'openapi' ? { type, url, operation_id: name } : { type: 'mcp', url, tool: name });
      }
    }
  }
  return result;
}
export function parseExcludedTasks(value: unknown, document: PoppyDocument): ExcludedTask[] {
  const tasks = object(value, 'excluded_tasks').tasks;
  if (!Array.isArray(tasks)) throw new ValidationError('tasks');
  return tasks.map(value => {
    const item = object(value, 'task');
    return { task: text(item.task, 'task', 200), ...('alternative' in item ? { alternative: parseAlternative(item.alternative, document) } : {}) };
  });
}
