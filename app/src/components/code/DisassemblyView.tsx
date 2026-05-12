import type { DisassemblyInstruction } from "@/lib/api";

interface DisassemblyViewProps {
  instructions: DisassemblyInstruction[];
}

export function DisassemblyView({ instructions }: DisassemblyViewProps) {
  return (
    <div className="p-4">
      <table className="w-full text-sm font-mono border-collapse">
        <tbody>
          {instructions.map((ins, i) => (
            <tr key={i} className="hover:bg-bg-hover">
              <td className="text-accent-blue pr-4 whitespace-nowrap tabular-nums">{ins.address}</td>
              <td className="text-text-muted pr-4 whitespace-nowrap">{ins.bytes}</td>
              <td className="text-accent-green pr-2 whitespace-nowrap font-semibold">{ins.mnemonic}</td>
              <td className="text-text-secondary whitespace-nowrap">{ins.operands}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
