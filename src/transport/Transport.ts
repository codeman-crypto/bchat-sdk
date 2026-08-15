import { SendMessageParams, Snode } from '../types.js';

export interface Transport {
  store(params: SendMessageParams, target: Snode): Promise<{ status: number; body: string }>;
  retrieve(params: any, target: Snode): Promise<{ status: number; body: string }>;
}
