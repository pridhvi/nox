import { useMemo, useState } from "react";

export type SortDirection = "asc" | "desc";

export type SortState<T extends string> = {
  key: T;
  direction: SortDirection;
};

export function useSortableRows<T, K extends string>(rows: T[], initial: SortState<K>, accessors: Record<K, (row: T) => string | number | boolean | undefined>) {
  const [sort, setSort] = useState(initial);
  const sortedRows = useMemo(() => {
    const accessor = accessors[sort.key];
    return [...rows].sort((left, right) => compareValues(accessor(left), accessor(right), sort.direction));
  }, [accessors, rows, sort]);

  function toggleSort(key: K) {
    setSort((current) => current.key === key ? { key, direction: current.direction === "asc" ? "desc" : "asc" } : { key, direction: "asc" });
  }

  return { sortedRows, sort, toggleSort };
}

export function sortLabel(active: boolean, direction: SortDirection) {
  if (!active) {
    return "";
  }
  return direction === "asc" ? " ↑" : " ↓";
}

function compareValues(left: string | number | boolean | undefined, right: string | number | boolean | undefined, direction: SortDirection) {
  const multiplier = direction === "asc" ? 1 : -1;
  if (typeof left === "number" && typeof right === "number") {
    return (left - right) * multiplier;
  }
  const leftText = String(left ?? "").toLowerCase();
  const rightText = String(right ?? "").toLowerCase();
  return leftText.localeCompare(rightText) * multiplier;
}
