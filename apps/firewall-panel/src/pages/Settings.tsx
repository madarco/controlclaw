import { KeyRound, Globe, LockKeyhole } from "lucide-react";
import { PageHead } from "@controlclaw/console-ui/kit/PageHead";
import { Card, Sec } from "@controlclaw/console-ui/kit/console-ui";
import { ModelKeysCard } from "./ModelKeys";
import { AdminPasswordCard } from "./AdminPassword";

function Later() {
  return <Card className="px-4 py-3 text-[13.5px] text-ink-2">Coming in a later update of the firewall.</Card>;
}

export function SettingsPage() {
  return (
    <>
      <PageHead title="Settings" sub="This firewall's model keys, admin password and exit." />
      <Sec id="ai-models" icon={KeyRound} title="AI model keys" sub="Your own keys, for the firewall's AI review." className="mt-0">
        <ModelKeysCard />
      </Sec>
      <Sec icon={LockKeyhole} title="Admin password" sub="The password for this panel.">
        <AdminPasswordCard />
      </Sec>
      <Sec icon={Globe} title="Your own exit proxy" sub="Send some sites' traffic out through a proxy of yours.">
        <Later />
      </Sec>
    </>
  );
}
