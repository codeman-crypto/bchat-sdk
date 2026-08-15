declare module 'lodash.shuffle' {
  function shuffle<T>(collection: readonly T[] | null | undefined): T[];
  export = shuffle;
}
