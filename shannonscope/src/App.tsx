import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Shield, HardDrive, Search, Skull, FileText, Database, Activity, Target, LayoutDashboard, Binary, FolderOpen } from "lucide-react";
import "./index.css";

// --- Types ---
type CarvedArtifact = {
  file_type: string;
  start_offset: number;
  size_bytes: number;
  output_path: string;
  sha256_checksum: string;
  is_fragmented_candidate: boolean;
  confidence_score: number;
  regex_strings: string[];
  threat_tags: string[];
};

type AuditEntry = {
  index: number;
  timestamp: number;
  action: string;
  target: string;
  status: string;
  operator_id: string;
  previous_hash: string;
  record_hash: string;
};

type DriveInfo = {
  target: string;
  serial_number: string;
  firmware_revision: string;
  is_rotational: boolean;
};

type DriveEnumInfo = {
  path: string;
  size_gb: number;
  is_removable: boolean;
  is_system_drive: boolean;
  label: string;
};

type TimelineEvent = {
  file_path: string;
  timestamp: number;
  event_type: string;
};

export default function App() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [target, setTarget] = useState("");
  const [availableDrives, setAvailableDrives] = useState<DriveEnumInfo[]>([]);
  const [driveInfo, setDriveInfo] = useState<DriveInfo | null>(null);
  const [fileTarget, setFileTarget] = useState("");
  const [timelineEvents, setTimelineEvents] = useState<TimelineEvent[]>([]);

  const handleGenerateTimeline = async () => {
    if (!target) return;
    if (!isSandboxed) {
      setStatusMsg("Drive must be safely sandboxed (mounted) first!");
      return;
    }
    setIsProcessing(true);
    try {
      const mountPoint = `/mnt/shannon_sandbox_${target.replace("/dev/", "")}`;
      const events: any = await invoke("generate_timeline", { mountPoint });
      setTimelineEvents(events);
      setStatusMsg(`Extracted ${events.length} timeline events!`);
    } catch (e: any) {
      setStatusMsg(`Timeline Error: ${e}`);
    }
    setIsProcessing(false);
  };
  const [artifacts, setArtifacts] = useState<CarvedArtifact[]>([]);
  const [auditTrail, setAuditTrail] = useState<AuditEntry[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isSandboxed, setIsSandboxed] = useState(false);
  
  const handleSandboxToggle = async () => {
    if (!target) return;
    setIsProcessing(true);
    try {
      if (isSandboxed) {
        const res: any = await invoke("sandbox_unmount", { target });
        setStatusMsg(res.message);
        setIsSandboxed(false);
      } else {
        const res: any = await invoke("sandbox_mount", { target });
        setStatusMsg(res.message);
        setIsSandboxed(true);
      }
    } catch (e: any) {
      setStatusMsg(`Sandbox Error: ${e}`);
    }
    setIsProcessing(false);
  };
  const [wipeProfile, setWipeProfile] = useState("dod_3pass");
  const [statusMsg, setStatusMsg] = useState("");
  const [hexViewData, setHexViewData] = useState<string | null>(null);

  // --- Backend Hooks ---
  const fetchDrives = async () => {
    try {
      const drives = await invoke<DriveEnumInfo[]>("enumerate_drives");
      setAvailableDrives(drives);
      if (drives.length > 0 && !target) setTarget(drives[0].path);
    } catch (e) {
      console.error("Failed to load drives", e);
    }
  };

  const loadAuditTrail = async () => {
    try {
      const trail = await invoke<AuditEntry[]>("get_audit_trail");
      setAuditTrail(trail);
    } catch (e) {
      console.error("Failed to load audit trail", e);
    }
  };

  const probeDrive = async (probeTarget: string) => {
    setTarget(probeTarget);
    try {
      const info = await invoke<DriveInfo>("run_get_drive_info", { target: probeTarget });
      setDriveInfo(info);
      setStatusMsg(`Target Probed: Serial ${info.serial_number}`);
    } catch (e) {
      setDriveInfo(null);
      setStatusMsg(`Probe unavailable for ${probeTarget}. Ensure Administrator/root access.`);
    }
  };

  useEffect(() => {
    loadAuditTrail();
    fetchDrives();
  }, []);

  // --- Handlers ---
  const handleRecover = async () => {
    setIsProcessing(true);
    setStatusMsg("Executing Deep Silicon Carver Engine (64MB Window)...");
    setArtifacts([]);
    setHexViewData(null);
    try {
      // run_file_recovery(target: String, output: String)
      const results = await invoke<CarvedArtifact[]>("run_file_recovery", { target: target, output: "shannonscope/recovered" });
      setArtifacts(results);
      setStatusMsg(`Carving complete. Extracted ${results.length} evidence artifacts.`);
    } catch (e: any) {
      setStatusMsg(`Carver Error: ${e}`);
    }
    setIsProcessing(false);
    loadAuditTrail();
  };

  const handleForensicClone = async () => {
    setIsProcessing(true);
    setStatusMsg("Creating Bit-for-Bit Forensic DD Image...");
    try {
      // run_forensic_clone(target: String, output_dir: String)
      await invoke("run_forensic_clone", { target: target, outputDir: "shannonscope/reports" });
      setStatusMsg(`Forensic Clone created successfully!`);
    } catch (e: any) {
      setStatusMsg(`Imaging Error: ${e}`);
    }
    setIsProcessing(false);
    loadAuditTrail();
  };

  const handleWipe = async () => {
    setIsProcessing(true);
    setStatusMsg(`Executing sanitization profile: ${wipeProfile}`);
    try {
      // run_drive_sanitization(target: String, profile_type: String)
      await invoke("run_drive_sanitization", { target: target, profileType: wipeProfile });
      setStatusMsg(`Sanitization complete.`);
    } catch (e: any) {
      setStatusMsg(`Sanitizer Error: ${e}`);
    }
    setIsProcessing(false);
    loadAuditTrail();
  };

  const handleFileWipe = async () => {
    if (!fileTarget) return;
    setIsProcessing(true);
    setStatusMsg(`Shredding specific target: ${fileTarget}`);
    try {
      // run_file_sanitization(target: String, profile_type: String)
      await invoke("run_file_sanitization", { target: fileTarget, profileType: "dod_3pass" });
      setStatusMsg(`File shredded securely.`);
    } catch (e: any) {
      setStatusMsg(`Shred Error: ${e}`);
    }
    setIsProcessing(false);
    loadAuditTrail();
  };

  const handleGeneratePdf = async () => {
    try {
      // run_export_report(artifacts: Vec<CarvedArtifact>, out_path: String)
      await invoke("run_export_report", { artifacts: artifacts, outPath: "shannonscope/reports/audit_certificate.pdf" });
      setStatusMsg("PDF Audit Certificate generated in reports/");
    } catch (e: any) {
      setStatusMsg(`PDF Error: ${e}`);
    }
  };

  const handleHexView = async (path: string) => {
    try {
      // run_hex_view(path: String)
      const hex = await invoke<string>("run_hex_view", { path: path });
      setHexViewData(hex);
    } catch (e: any) {
      setStatusMsg(`Hex View Error: ${e}`);
    }
  };

  const handleOpenFolder = async () => {
    try {
      // open_folder(path: String)
      await invoke("open_folder", { path: "shannonscope/recovered" });
    } catch (e: any) {
      setStatusMsg(`Failed to open folder: ${e}`);
    }
  };

  // --- Sub-Components ---
  const TopBar = () => (
    <div className="bg-gray-50 border-b border-gray-300 p-4 flex justify-between items-center shadow-lg sticky top-0 z-10">
      <div className="flex items-center gap-3">
        <Shield className="text-blue-600" size={28} />
        <div>
          <h1 className="text-gray-900 font-black tracking-widest text-lg uppercase">ShannonScope</h1>
          <p className="text-[10px] text-gray-500 uppercase tracking-widest">Digital Forensics Suite 2.0</p>
        </div>
      </div>
      <div className="flex items-center gap-4">
        {isProcessing && (
          <div className="flex items-center gap-2 text-blue-600 text-xs font-mono bg-blue-100 px-3 py-1 rounded border border-blue-300">
            <Activity size={14} className="animate-spin" />
            PROCESSING...
          </div>
        )}
        <div className="text-xs text-gray-600 bg-white px-3 py-1.5 rounded border border-gray-300 font-mono flex items-center gap-2">
          <Target size={14} className="text-green-500" />
          ACTIVE TARGET: <span className="text-gray-900 font-bold">{target || "NONE"}</span>
        </div>
      </div>
    </div>
  );

  const SideBar = () => {
    const tabs = [
      { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
      { id: 'carver', label: 'Silicon Carver', icon: Search },
      { id: 'timeline', label: 'Timeline Analyzer', icon: Activity },
      { id: 'sanitizer', label: 'Data Sanitization', icon: Skull },
      { id: 'ledger', label: 'Audit Ledger', icon: Database },
    ];
    return (
      <div className="w-64 bg-gray-50 border-r border-gray-300 flex flex-col h-[calc(100vh-73px)]">
        <div className="p-4 space-y-2 flex-1">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded text-sm tracking-wider uppercase transition-all ${activeTab === tab.id ? 'bg-blue-100 text-blue-600 border border-blue-300 shadow-inner' : 'text-gray-600 hover:bg-gray-200 hover:text-gray-900 border border-transparent'}`}
            >
              <tab.icon size={18} />
              {tab.label}
            </button>
          ))}
        </div>
        <div className="p-4 border-t border-gray-300">
           <button onClick={handleOpenFolder} className="w-full flex items-center justify-center gap-2 bg-gray-800 hover:bg-gray-700 border border-gray-300 text-gray-700 py-2.5 rounded text-xs uppercase tracking-widest transition-all">
            <FolderOpen size={16} /> Evidence Folder
          </button>
        </div>
      </div>
    );
  };

  // --- Views ---
  const DashboardView = () => (
    <div className="p-6 space-y-6 animate-fade-in">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white border border-gray-300 p-6 rounded-lg shadow-xl">
          <div className="flex items-center gap-3 text-gray-600 mb-4">
            <HardDrive size={24} className="text-blue-500" />
            <h2 className="uppercase tracking-widest text-sm font-bold text-gray-800">Target Selection</h2>
          </div>
          <select 
            className="w-full bg-gray-50 border border-gray-300 text-white rounded px-3 py-2 text-sm focus:border-blue-600 focus:outline-none mb-3"
            value={target}
            onChange={(e) => probeDrive(e.target.value)}
          >
            <option value="" className="bg-gray-100 text-gray-900">SELECT TARGET DEVICE</option>
            {availableDrives.map((d) => (
              <option key={d.path} value={d.path} className="bg-gray-100 text-gray-900">
                {d.path} ({d.size_gb.toFixed(1)} GB) {d.is_removable ? '[USB]' : ''}
              </option>
            ))}
          </select>
          <div className="flex justify-between items-center mt-4 text-xs">
            <span className="text-gray-500">Available Drives:</span>
            <span className="text-blue-600 font-bold">{availableDrives.length}</span>
          </div>
          <button onClick={() => fetchDrives()} className="w-full mt-4 text-[10px] text-gray-600 hover:text-gray-800 uppercase tracking-widest border border-gray-300 hover:border-gray-600 rounded py-1">Refresh Drives</button>
        </div>

        <div className="bg-white border border-gray-300 p-6 rounded-lg shadow-xl md:col-span-2">
          <h2 className="uppercase tracking-widest text-sm font-bold text-gray-700 mb-4 border-b border-gray-300 pb-2">Hardware Probe Data</h2>
          {driveInfo ? (
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div className="bg-white p-3 rounded border border-gray-300">
                <span className="block text-[10px] text-gray-500 uppercase tracking-widest mb-1">Serial Number</span>
                <span className="text-blue-600 font-mono">{driveInfo.serial_number}</span>
              </div>
              <div className="bg-white p-3 rounded border border-gray-300">
                <span className="block text-[10px] text-gray-500 uppercase tracking-widest mb-1">Firmware Rev</span>
                <span className="text-gray-700 font-mono">{driveInfo.firmware_revision}</span>
              </div>
              <div className="bg-white p-3 rounded border border-gray-300">
                <span className="block text-[10px] text-gray-500 uppercase tracking-widest mb-1">Drive Type</span>
                <span className={driveInfo.is_rotational ? "text-orange-400" : "text-green-400"}>
                  {driveInfo.is_rotational ? "HDD (Rotational)" : "SSD / Flash / NVMe"}
                </span>
              </div>
              <div className="bg-white p-3 rounded border border-gray-300">
                <span className="block text-[10px] text-gray-500 uppercase tracking-widest mb-1">Security Status</span>
                <span className="text-red-400 uppercase">Sanitization Required</span>
              </div>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center text-gray-600 italic text-sm">
              No hardware probe data available. Select a valid target.
            </div>
          )}
        </div>
      </div>
      
      {statusMsg && (
        <div className="p-4 bg-white/50 border-l-4 border-blue-600 text-sm font-mono text-blue-600 shadow-lg flex items-center gap-3">
          <Activity size={16} />
          {statusMsg}
        </div>
      )}
    </div>
  );

  const CarverView = () => (
    <div className="p-6 h-full flex flex-col animate-fade-in">
      <div className="flex justify-between items-center mb-6 border-b border-gray-300 pb-4">
        <div>
          <h2 className="text-lg uppercase tracking-widest text-purple-400 font-bold flex items-center gap-2">
            <Search size={20} /> Deep Silicon Carver
          </h2>
          <p className="text-xs text-gray-500 mt-1">Extract orphaned fragments and hidden multimedia payloads</p>
        </div>
        <div className="flex gap-3">
          <button 
            onClick={handleSandboxToggle} 
            disabled={isProcessing || !target} 
            className={`px-4 py-2 rounded shadow-lg text-xs uppercase tracking-widest transition-all flex items-center gap-2 border ${isSandboxed ? 'bg-emerald-900/50 border-emerald-500 text-emerald-300' : 'bg-gray-800/50 border-gray-600 text-gray-700 hover:bg-gray-700/80'}`}
          >
            {isSandboxed ? 'Unmount Sandbox' : 'Safe Mount Sandbox'}
          </button>
          <button onClick={handleForensicClone} disabled={isProcessing || !target} className="bg-blue-900/50 hover:bg-blue-800/80 border border-blue-800 disabled:opacity-50 text-white px-4 py-2 rounded shadow-lg text-xs uppercase tracking-widest transition-all flex items-center gap-2">
            <Database size={16}/> Forensic Clone (.DD)
          </button>
          <button onClick={handleRecover} disabled={isProcessing || !target} className="bg-blue-600 hover:bg-blue-700 border border-blue-600 disabled:opacity-50 text-white px-6 py-2 rounded shadow-[0_0_15px_rgba(6,182,212,0.3)] text-xs uppercase tracking-widest font-bold transition-all flex items-center gap-2">
            <Binary size={16}/> Execute Carver
          </button>
        </div>
      </div>

      {hexViewData && (
        <div className="mb-6 p-4 bg-white border border-blue-300 rounded relative shadow-2xl">
          <button onClick={() => setHexViewData(null)} className="absolute top-2 right-2 text-gray-500 hover:text-gray-900 text-xs bg-gray-100 px-2 py-1 rounded">Close</button>
          <h3 className="text-xs text-blue-600 mb-2 font-bold uppercase tracking-widest">Hex Inspector (First 256 Bytes)</h3>
          <pre className="text-[10px] text-gray-600 font-mono whitespace-pre overflow-x-auto">{hexViewData}</pre>
        </div>
      )}

      <div className="flex-1 bg-white border border-gray-300 rounded-lg p-6 overflow-y-auto shadow-inner">
        {artifacts.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-gray-600 space-y-4">
            <Search size={48} className="opacity-20" />
            <p className="uppercase tracking-widest text-sm">No evidence extracted in current session.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
            {artifacts.map((art, idx) => (
              <div key={idx} className={`p-4 rounded border transition-colors group ${art.threat_tags.length > 0 ? 'bg-red-950/20 border-red-900/50' : 'bg-white border-gray-300'}`}>
                <div className="flex justify-between items-start mb-3">
                  <div className="text-xs font-bold text-gray-900 uppercase tracking-wider flex items-center gap-2">
                    <FileText size={14} className={art.threat_tags.length > 0 ? 'text-red-500' : 'text-blue-600'} />
                    {art.file_type}
                  </div>
                  <div className={`text-[10px] px-2 py-0.5 rounded border ${art.confidence_score > 0.8 ? 'border-green-800 text-green-400 bg-green-900/20' : 'border-yellow-800 text-yellow-400 bg-yellow-900/20'}`}>
                    {(art.confidence_score * 100).toFixed(0)}% CONF
                  </div>
                </div>
                
                {art.threat_tags.length > 0 && (
                  <div className="flex gap-2 mb-3 flex-wrap">
                    {art.threat_tags.map(t => <span key={t} className="bg-red-900 text-white text-[9px] px-2 py-0.5 rounded border border-red-500 uppercase font-bold shadow-[0_0_5px_rgba(239,68,68,0.5)]">{t}</span>)}
                  </div>
                )}
                
                {art.file_type === "REGEX_HARVEST_DATA" ? (
                  <div className="text-[10px] text-gray-600 h-24 overflow-y-auto border border-gray-300 p-2 bg-gray-50 rounded">
                    {art.regex_strings.map((str, i) => <div key={i} className="text-purple-400 break-all mb-1">{str}</div>)}
                  </div>
                ) : (
                  <div className="text-[11px] text-gray-500 space-y-2 bg-gray-50 p-3 rounded border border-gray-300">
                    <div className="flex justify-between border-b border-gray-300 pb-1">
                      <span>Offset:</span><span className="text-cyan-600 font-mono">0x{art.start_offset.toString(16).toUpperCase()}</span>
                    </div>
                    <div className="flex justify-between border-b border-gray-300 pb-1">
                      <span>Size:</span><span className="text-gray-700 font-mono">{(art.size_bytes / 1024).toFixed(1)} KB</span>
                    </div>
                    <div className="flex flex-col pt-1 gap-2">
                      <div className="truncate" title={art.sha256_checksum}>
                        <span className="text-gray-600">SHA256: </span><span className="text-gray-600 font-mono">{art.sha256_checksum.substring(0, 24)}...</span>
                      </div>
                      <button onClick={() => handleHexView(art.output_path)} className="self-end text-[9px] bg-gray-800 hover:bg-gray-700 px-3 py-1 rounded border border-gray-600 uppercase text-gray-900 transition-all">
                        Inspect Hex
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );

  const TimelineView = () => (
    <div className="p-6 h-full flex flex-col animate-fade-in">
      <div className="flex justify-between items-center mb-6 border-b border-gray-300 pb-4">
        <div>
          <h2 className="text-lg uppercase tracking-widest text-indigo-400 font-bold flex items-center gap-2">
            <Activity size={20} /> Super-Timeline Analyzer
          </h2>
          <p className="text-xs text-gray-500 mt-1">Chronological mapping of MAC timestamps</p>
        </div>
        <button 
          onClick={handleGenerateTimeline}
          disabled={isProcessing || !target}
          className="bg-indigo-900/50 hover:bg-indigo-800/80 border border-indigo-500 text-white px-6 py-2 rounded text-xs uppercase tracking-widest font-bold transition-all shadow-[0_0_15px_rgba(99,102,241,0.3)] disabled:opacity-50"
        >
          Generate Timeline
        </button>
      </div>

      <div className="flex-1 bg-white border border-gray-300 rounded-lg p-6 overflow-y-auto shadow-inner">
        {timelineEvents.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-gray-600 space-y-4">
            <Activity size={48} className="opacity-20" />
            <p className="uppercase tracking-widest text-sm text-center">No timeline data.<br/>Mount the drive and click Generate.</p>
          </div>
        ) : (
          <div className="space-y-1 border-l-2 border-indigo-900 ml-4">
            {timelineEvents.map((event, idx) => (
              <div key={idx} className="relative pl-6 py-2 hover:bg-gray-100 group">
                <div className={`absolute w-3 h-3 rounded-full -left-[7px] top-3 
                  ${event.event_type === 'MODIFIED' ? 'bg-orange-500' : 
                    event.event_type === 'CREATED' ? 'bg-emerald-500' : 'bg-blue-500'}`}>
                </div>
                <div className="flex justify-between items-start">
                  <div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-widest mr-3
                      ${event.event_type === 'MODIFIED' ? 'text-orange-400 border-orange-900 bg-orange-900/20' : 
                        event.event_type === 'CREATED' ? 'text-emerald-400 border-emerald-900 bg-emerald-900/20' : 
                        'text-blue-400 border-blue-900 bg-blue-900/20'}`}>
                      {event.event_type}
                    </span>
                    <span className="text-gray-700 font-mono text-xs">{event.file_path}</span>
                  </div>
                  <span className="text-gray-500 font-mono text-[10px]">
                    {new Date(event.timestamp * 1000).toLocaleString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );

  const SanitizerView = () => (
    <div className="p-6 max-w-4xl mx-auto animate-fade-in">
      <h2 className="text-lg uppercase tracking-widest text-red-500 font-bold mb-6 flex items-center gap-2 border-b border-gray-300 pb-4">
        <Skull size={20} /> Cryptographic Data Sanitization
      </h2>
      
      <div className="bg-white border border-red-900/30 p-8 rounded-lg shadow-[0_0_30px_rgba(220,38,38,0.05)]">
        <div className="mb-8">
          <label className="block text-xs uppercase tracking-widest text-gray-600 mb-3 font-bold">Sanitization Standard</label>
          <select 
            className="w-full bg-white border border-gray-300 text-red-400 rounded px-4 py-3 text-sm focus:border-red-500 focus:outline-none"
            value={wipeProfile}
            onChange={(e) => setWipeProfile(e.target.value)}
          >
            <option value="nist_clear" className="bg-gray-100 text-gray-900">NIST SP 800-88 (1-Pass Clear)</option>
            <option value="dod_3pass" className="bg-gray-100 text-gray-900">DoD 5220.22-M (3-Pass Wipe)</option>
            <option value="hardware_purge" className="bg-gray-100 text-gray-900">Hardware Crypto-Erase (BLKDISCARD)</option>
          </select>
          <p className="text-[10px] text-gray-500 mt-2 uppercase">Warning: Execution of these protocols results in permanent, mathematically irreversible data destruction.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="border border-gray-300 bg-white p-6 rounded-lg text-center flex flex-col items-center justify-center">
            <HardDrive size={32} className="text-gray-500 mb-4" />
            <h3 className="text-gray-900 uppercase tracking-widest text-sm mb-2 font-bold">Full Device Purge</h3>
            <p className="text-xs text-gray-500 mb-6">Obliterate all data blocks on {target || "NO TARGET"}</p>
            <button 
              onClick={handleWipe}
              disabled={isProcessing || !target}
              className="w-full bg-red-900/40 hover:bg-red-700/80 border border-red-700 disabled:opacity-50 text-white py-3 rounded text-sm uppercase tracking-widest font-black transition-all shadow-[0_0_15px_rgba(220,38,38,0.2)]"
            >
              Initiate Drive Purge
            </button>
          </div>

          <div className="border border-gray-300 bg-white p-6 rounded-lg text-center flex flex-col items-center justify-center">
            <FileText size={32} className="text-gray-500 mb-4" />
            <h3 className="text-gray-900 uppercase tracking-widest text-sm mb-2 font-bold">Targeted Shredding</h3>
            <p className="text-xs text-gray-500 mb-4">Shred a specific file path</p>
            <input 
              type="text"
              placeholder="/path/to/evidence.txt"
              className="w-full bg-white border border-gray-300 text-gray-900 rounded px-3 py-2 text-xs mb-4 focus:border-red-500 focus:outline-none"
              value={fileTarget}
              onChange={(e) => setFileTarget(e.target.value)}
            />
            <button 
              onClick={handleFileWipe}
              disabled={isProcessing || !fileTarget}
              className="w-full bg-orange-900/40 hover:bg-orange-700/80 border border-orange-700 disabled:opacity-50 text-white py-3 rounded text-sm uppercase tracking-widest font-black transition-all"
            >
              Shred Target
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  const LedgerView = () => (
    <div className="p-6 h-full flex flex-col animate-fade-in">
      <div className="flex justify-between items-center mb-6 border-b border-gray-300 pb-4">
        <div>
          <h2 className="text-lg uppercase tracking-widest text-emerald-500 font-bold flex items-center gap-2">
            <Database size={20} /> Merkle Audit Ledger
          </h2>
          <p className="text-xs text-gray-500 mt-1">Cryptographically verifiable chain of custody logs</p>
        </div>
        <button onClick={handleGeneratePdf} className="bg-emerald-900/30 hover:bg-emerald-800/60 border border-emerald-700 text-white px-4 py-2 rounded text-xs uppercase tracking-widest font-bold transition-all shadow-[0_0_10px_rgba(16,185,129,0.2)]">
          Export Chain Certificate (PDF)
        </button>
      </div>

      <div className="flex-1 bg-gray-50 border border-gray-300 rounded-lg overflow-y-auto p-4 shadow-inner">
        {auditTrail.length === 0 ? (
          <div className="h-full flex items-center justify-center text-gray-600 italic">Awaiting genesis block...</div>
        ) : (
          <div className="space-y-3">
            {auditTrail.map((entry) => (
              <div key={entry.index} className="bg-white p-4 rounded-lg border border-gray-300 font-mono text-[11px] shadow-sm hover:border-gray-600 transition-colors">
                <div className="flex justify-between items-center mb-2 pb-2 border-b border-gray-300">
                  <div className="flex items-center gap-3">
                    <span className="bg-gray-800 text-emerald-400 px-2 py-0.5 rounded font-bold">BLOCK {entry.index}</span>
                    <span className="text-gray-900 font-bold tracking-widest">OP_{entry.action}</span>
                    <span className="text-gray-500">{entry.target}</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded border font-bold ${entry.status.includes('SUCCESS') || entry.status.includes('CLEAN') ? 'bg-green-900/20 text-green-500 border-green-800' : 'bg-red-900/20 text-red-500 border-red-800'}`}>
                    {entry.status}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-4 mt-3">
                  <div>
                    <span className="block text-[9px] text-gray-600 uppercase mb-1">Previous Hash (Chain)</span>
                    <span className="text-gray-600 break-all">{entry.previous_hash}</span>
                  </div>
                  <div>
                    <span className="block text-[9px] text-emerald-700 uppercase mb-1">Block Hash (SHA-256)</span>
                    <span className="text-emerald-500 font-bold break-all">{entry.record_hash}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-100 text-gray-800 font-sans selection:bg-cyan-900 flex flex-col overflow-hidden h-screen">
      <TopBar />
      <div className="flex flex-1 overflow-hidden">
        <SideBar />
        <div className="flex-1 overflow-y-auto bg-gradient-to-br from-[#050709] to-gray-50 relative">
          {activeTab === 'dashboard' && <DashboardView />}
          {activeTab === 'carver' && <CarverView />}
          {activeTab === 'timeline' && <TimelineView />}
          {activeTab === 'sanitizer' && <SanitizerView />}
          {activeTab === 'ledger' && <LedgerView />}
        </div>
      </div>
    </div>
  );
}
