export interface CursorPaginationOptions {
  cursor?: string;
  limit?: number;
  defaultLimit?: number;
  maxLimit?: number;
}

export interface CursorPaginationResult<T> {
  data: T[];
  pagination: {
    cursor: string | null;
    nextCursor: string | null;
    hasMore: boolean;
    limit: number;
    totalCount: number;
    totalPages: number;
  };
}

export const getCursorPaginationParams = (options: CursorPaginationOptions) => {
  const defaultLimit = options.defaultLimit ?? 100;
  const maxLimit = options.maxLimit ?? 100;
  const limit = Math.max(1, Math.min(maxLimit, options.limit ?? defaultLimit));
  return {
    cursor: options.cursor ?? undefined,
    limit,
  };
};

export const paginateWithCursor = async <T extends { id: string }>(
  findManyFn: (args: { take: number; skip?: number; cursor?: { id: string } }) => Promise<T[]>,
  countFn: () => Promise<number>,
  options: CursorPaginationOptions
): Promise<CursorPaginationResult<T>> => {
  const { cursor, limit } = getCursorPaginationParams(options);

  // Query limit + 1 items and total count concurrently
  const [items, totalCount] = await Promise.all([
    findManyFn({
      take: limit + 1,
      skip: cursor ? 1 : undefined,
      cursor: cursor ? { id: cursor } : undefined,
    }),
    countFn(),
  ]);

  const hasMore = items.length > limit;
  const data = hasMore ? items.slice(0, limit) : items;
  // eslint-disable-next-line unicorn/prefer-at
  const nextCursor = hasMore && data.length > 0 ? data[data.length - 1].id : null;
  const totalPages = Math.ceil(totalCount / limit);

  return {
    data,
    pagination: {
      cursor: cursor ?? null,
      nextCursor,
      hasMore,
      limit,
      totalCount,
      totalPages,
    },
  };
};
