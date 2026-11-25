"use client";

import { useState } from "react";
import { NativeSelect } from "../../ui/native-select";
import { cn } from "../../lib/utils";
import { DOCTOR_CLI_NAMES, doctorFormPick, doctorModelsForCli, doctorSelectedModel } from "../../lib/doctor-models";

type Cli = "claude" | "codex" | "pi";
type Credential = { id: string; label: string; provider: string; clis: readonly Cli[]; models: { id: string; name: string }[] };

/**
 * The choice a Doctor form makes (coding agent, key, model): the default pick until the person
 * changes one, and the resets when a choice above changes. Shared by the Doctor tab, Ask Doctor on a
 * finding and the firewall's start page.
 */
export function useDoctorChoice<C extends Credential>(credentials: readonly C[] | null) {
  const [chosenCli, setCli] = useState<Cli | "">("");
  const [credentialId, setCredentialId] = useState("");
  const [model, setModel] = useState("");
  const pick = doctorFormPick(credentials ?? [], chosenCli, credentialId);
  const models = pick.credential ? doctorModelsForCli(pick.credential, pick.cli) : [];
  const selectedModel = doctorSelectedModel(models, model);
  return {
    ...pick,
    models,
    model: selectedModel,
    modelName: models.find((m) => m.id === selectedModel)?.name ?? selectedModel,
    /** True until the person changes anything: the pick is the organization's best. */
    isDefault: !chosenCli && !credentialId && !model,
    chooseCli: (cli: Cli) => {
      setCli(cli);
      setCredentialId("");
      setModel("");
    },
    chooseCredential: (id: string) => {
      setCli(pick.cli);
      setCredentialId(id);
      setModel("");
    },
    chooseModel: (id: string) => {
      setCli(pick.cli);
      setCredentialId(pick.credential?.id ?? "");
      setModel(id);
    },
  };
}

export type DoctorChoice<C extends Credential = Credential> = ReturnType<typeof useDoctorChoice<C>>;

/** The three pickers of a Doctor form. The caller lays them out with `className` and its own labels' style. */
export function DoctorPickers({ choice, labelClassName, selectClassName, id }: { choice: DoctorChoice; labelClassName?: string; selectClassName?: string; id?: string }) {
  const select = cn("w-full min-w-0 rounded-md border border-line bg-surface px-3 text-sm text-ink", selectClassName);
  return (
    <>
      <label className={labelClassName}>
        Coding agent
        <NativeSelect aria-label="Coding agent" id={id} className={select} value={choice.cli} onChange={(e) => choice.chooseCli(e.target.value as Cli)}>
          {Object.entries(DOCTOR_CLI_NAMES).map(([cli, name]) => (
            <option key={cli} value={cli}>
              {name}
            </option>
          ))}
        </NativeSelect>
      </label>
      <label className={labelClassName}>
        Pay with
        <NativeSelect aria-label="Pay with" className={select} value={choice.credential?.id ?? ""} onChange={(e) => choice.chooseCredential(e.target.value)}>
          {!choice.choices.length && <option value="">No compatible key</option>}
          {choice.choices.map((c) => (
            <option key={c.id} value={c.id}>
              {c.label}
            </option>
          ))}
        </NativeSelect>
      </label>
      <label className={labelClassName}>
        Model
        <NativeSelect aria-label="Model" className={select} value={choice.model} onChange={(e) => choice.chooseModel(e.target.value)}>
          {!choice.models.length && <option value="">No models available</option>}
          {choice.models.map((m) => (
            <option key={m.id} value={m.id}>
              {m.name}
            </option>
          ))}
        </NativeSelect>
      </label>
    </>
  );
}
