import {
  Router, Network, Server, HardDrive, Box, Cpu, Laptop, Smartphone, Printer,
  Camera, Home, Thermometer, Flame, Zap, Tv, Radio, HelpCircle, type LucideIcon,
} from "lucide-react";

/** Eine Gerätekategorie (`system.kind`) auf ein Icon abgebildet — passend zu den Bezeichnungen
 *  aus `KIND_LABELS` in backend/app/docs.py. Unbekannte oder neue Kinds fallen auf HelpCircle. */
const KIND_ICONS: Record<string, LucideIcon> = {
  router: Router,
  network: Network,
  server: Server,
  nas: HardDrive,
  container: Box,
  vm: Cpu,
  pc: Laptop,
  mobile: Smartphone,
  printer: Printer,
  camera: Camera,
  smarthome: Home,
  climate: Thermometer,
  heating: Flame,
  energy: Zap,
  media: Tv,
  iot: Radio,
  other: HelpCircle,
};

export function KindIcon({ kind, size = 16, className }: { kind: string; size?: number; className?: string }) {
  const Icon = KIND_ICONS[kind] ?? HelpCircle;
  return <Icon size={size} className={className} aria-hidden="true" />;
}
