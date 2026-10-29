import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { AnimatePresence, motion } from "motion/react";
import { X, ScanLine } from "lucide-react";
import { JsonDetails } from "./ui";

interface Selection {
  title: string;
  kind: string;
  description?: string;
  data: unknown;
}
const InspectorContext = createContext<(selection: Selection) => void>(
  () => {},
);
export const useInspector = () => useContext(InspectorContext);
export function InspectorProvider({ children }: { children: ReactNode }) {
  const [selection, setSelection] = useState<Selection | null>(null);
  const [open, setOpen] = useState(false);
  const close = useRef<HTMLButtonElement>(null);
  const origin = useRef<HTMLElement | null>(null);
  useEffect(() => {
    if (open) {
      origin.current = document.activeElement as HTMLElement;
      close.current?.focus();
    } else origin.current?.focus();
  }, [open]);
  return (
    <InspectorContext.Provider
      value={(value) => {
        setSelection(value);
        setOpen(true);
      }}
    >
      {children}
      {selection && !open && (
        <button className="inspector-reopen" onClick={() => setOpen(true)}>
          <ScanLine size={16} />
          Reopen inspector
        </button>
      )}
      <AnimatePresence>
        {open && selection && (
          <motion.aside
            initial={{ x: 50, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 50, opacity: 0 }}
            className="inspector panel"
            aria-label="Context inspector"
            onKeyDown={(e) => {
              if (e.key === "Escape") setOpen(false);
            }}
          >
            <div className="panel-header">
              <span className="eyebrow">{selection.kind}</span>
              <button
                ref={close}
                aria-label="Close inspector"
                onClick={() => setOpen(false)}
              >
                <X size={18} />
              </button>
            </div>
            <div className="inspector-body">
              <div className="inspector-symbol">
                <ScanLine size={28} />
              </div>
              <h2>{selection.title}</h2>
              <p>
                {selection.description ||
                  "Recorded backend data. Selecting an item does not execute an action."}
              </p>
              <JsonDetails value={selection.data} />
            </div>
          </motion.aside>
        )}
      </AnimatePresence>
    </InspectorContext.Provider>
  );
}
