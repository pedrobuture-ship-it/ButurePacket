import { Clock, Filter, Search } from "lucide-react";
import { Button, IconButton, Input } from "@/components/ui";
import { useUiStore } from "@/stores/ui";

export function FilterBar() {
  const { filterDraft, filter, setFilterDraft, applyFilter, clearFilter } = useUiStore();
  return (
    <form
      className="flex shrink-0 items-center gap-2 border-b border-line p-2"
      onSubmit={(e) => {
        e.preventDefault();
        applyFilter();
      }}
    >
      <Input
        id="global-filter"
        mono
        className="flex-1"
        icon={<Search size={14} />}
        placeholder="Filter packets... (e.g. dns, ip = 192.168.1.1, tcp && dst.port = 443)"
        aria-label="Filter"
        value={filterDraft}
        onChange={(e) => setFilterDraft(e.target.value)}
        onKeyDown={(e) => e.key === "Escape" && clearFilter()}
      />
      <Button type="submit" variant="secondary">
        Apply
      </Button>
      <IconButton label="Clear filter" active={filter !== ""} onClick={clearFilter}>
        <Filter size={15} />
      </IconButton>
      <IconButton label="Filter history" disabled>
        <Clock size={15} />
      </IconButton>
    </form>
  );
}
