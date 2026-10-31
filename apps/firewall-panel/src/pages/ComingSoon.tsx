import { Clock } from "lucide-react";
import { PageHead } from "@controlclaw/console-ui/kit/PageHead";
import { Card, EmptyState } from "@controlclaw/console-ui/kit/console-ui";

/** A V1 page whose API the firewall does not have yet. */
export function ComingSoon({ title, sub }: { title: string; sub?: string }) {
  return (
    <>
      <PageHead title={title} sub={sub} />
      <Card data-testid="coming-soon">
        <EmptyState icon={Clock} title="Coming soon">
          This page comes in a later update of the firewall.
        </EmptyState>
      </Card>
    </>
  );
}
