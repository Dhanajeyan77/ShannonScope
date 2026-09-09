import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./index.css";

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

function App() {
  const [target, setTarget] = useState("");
  const [availableDrives, setAvailableDrives] = useState<DriveEnumInfo[]>([]);
  const [driveInfo, setDriveInfo] = useState<DriveInfo | null>(null);
  const [fileTarget, setFileTarget] = useState("");
  const [artifacts, setArtifacts] = useState<CarvedArtifact[]>([]);
  const [auditTrail, setAuditTrail] = useState<AuditEntry[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [wipeProfile, setWipeProfile] = useState("dod_3pass");
  const [statusMsg, setStatusMsg] = useState("");
  const [hexViewData, setHexViewData] = useState<string | null>(null);

  const fetchDrives = async () => {
    try {
      const drives = await invoke<DriveEnumInfo[]>("enumerate_drives");
      setAvailableDrives(drives);
      if (drives.length > 0 && !target) {
        setTarget(drives[0].path);
      }
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

  const probeDrive = async (overrideTarget?: string) => {
    const probeTarget = overrideTarget || target;
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

  const handleRecover = async () => {
    setIsProcessing(true);
    setStatusMsg("Scanning sectors with 4MB Sliding Window...");
    setArtifacts([]);
    setHexViewData(null);
    try {
      const results = await invoke<CarvedArtifact[]>("run_file_recovery", {
        target,
        output: "recovered"
      });
      setArtifacts(results);
      setStatusMsg(`Recovery complete: Found ${results.length} artifacts.`);
    } catch (e) {
      setStatusMsg(`Error: ${e}`);
    }
    setIsProcessing(false);
    loadAuditTrail();
  };

  const handleClone = async () => {
    setIsProcessing(true);
    setStatusMsg(`Creating forensic bit-stream clone of ${target}...`);
    try {
      const res = await invoke<{image_path: string, sha256_hash: string, bytes_copied: number}>("run_forensic_clone", {
        target,
        outputDir: "recovered"
      });
      setStatusMsg(`Image created! SHA-256: ${res.sha256_hash}`);
      loadAuditTrail();
    } catch (e) {
      setStatusMsg(`Clone Error: ${e}`);
    }
    setIsProcessing(false);
  };

  const handleOpenFolder = async () => {
    try {
      await invoke("open_folder", { path: "recovered" });
    } catch (e) {
      setStatusMsg(`Error opening folder: ${e}`);
    }
  };

  const handleDriveWipe = async () => {
    setIsProcessing(true);
    setStatusMsg(`Sanitizing disk using profile: ${wipeProfile}... (Executing Passes)`);
    try {
      const success = await invoke<boolean>("run_drive_sanitization", {
        target,
        profileType: wipeProfile
      });
      setStatusMsg(success ? "Drive Sanitized and Verified (O_SYNC Kernel flush)!" : "Sanitization verification failed.");
    } catch (e) {
      setStatusMsg(`Error: ${e}`);
    }
    setIsProcessing(false);
    loadAuditTrail();
  };

  const handleFileWipe = async () => {
    if (!fileTarget) { setStatusMsg("Please specify a file to wipe."); return; }
    setIsProcessing(true);
    setStatusMsg(`Executing Secure Eraser: Overwriting & Mutilating Inode for ${fileTarget}...`);
    try {
      const success = await invoke<boolean>("run_file_sanitization", {
        target: fileTarget,
        profileType: wipeProfile
      });
      setStatusMsg(success ? "File Securely Erased and Metadata Scrubbed!" : "File Erase Failed.");
      setFileTarget("");
    } catch (e) {
      setStatusMsg(`Error: ${e}`);
    }
    setIsProcessing(false);
    loadAuditTrail();
  };

  const handleGeneratePdf = async () => {
    try {
      await invoke("run_export_report", { artifacts, outPath: "reports/Recovery_Report.pdf" });
      setStatusMsg("Case Report Generated: reports/Recovery_Report.pdf");
    } catch (e) {
      setStatusMsg(`Error generating PDF: ${e}`);
    }
  };

  const handleHexView = async (path: string) => {
    if (path === "MEMORY_ONLY") return;
    try {
      const hexDump = await invoke<string>("run_hex_view", { path });
      setHexViewData(hexDump);
    } catch (e) {
      setStatusMsg(`Failed to open hex view: ${e}`);
    }
  };

  return (
    <div className="min-h-screen bg-[#0d1117] text-gray-300 p-8 font-mono tracking-tight selection:bg-cyan-900">
      <header className="mb-8 border-b border-gray-800 pb-4 flex justify-between items-end">
        <div>
          <h1 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-600 uppercase tracking-widest">
            ShannonScope
          </h1>
          <p className="text-gray-500 text-sm uppercase mt-1 tracking-widest">Bare-Metal Forensic & Sanitization Engine</p>
        </div>
        <div className="text-right text-xs text-gray-500">
          <p>HOST: Linux Kernel</p>
          <p>MEM BOUNDARY: 8GB Strict</p>
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        
        {/* Controls Panel */}
        <div className="md:col-span-5 bg-[#161b22] p-6 rounded-lg border border-gray-800 shadow-2xl relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyan-500 to-blue-500"></div>
          
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-sm uppercase tracking-widest text-cyan-500 font-bold">Hardware Target</h2>
            <button onClick={fetchDrives} className="text-[9px] uppercase border border-gray-700 bg-gray-800 px-2 py-0.5 rounded text-gray-400 hover:text-white">Refresh Drives</button>
          </div>
          
          <div className="mb-4">
            <div className="flex flex-col gap-2 mb-2">
              <select 
                onChange={(e) => probeDrive(e.target.value)}
                value={target || ""}
                className="w-full bg-[#0d1117] border border-gray-700 rounded px-3 py-2 text-white text-sm focus:border-cyan-500 outline-none"
              >
                <option value="" disabled>-- Select an attached drive --</option>
                {availableDrives.map((d, i) => (
                  <option key={i} value={d.path}>
                    {d.label} {d.is_system_drive ? " [SYSTEM DRIVE - DO NOT WIPE]" : ""}
                  </option>
                ))}
              </select>
              <div className="flex gap-2">
                <input 
                  type="text" 
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="flex-1 bg-[#0d1117] border border-gray-700 rounded px-3 py-2 text-white text-sm focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none transition-all"
                  placeholder="Or manually type path (e.g. \\.\PhysicalDrive1)"
                />
                <button 
                  onClick={() => probeDrive()}
                  className="bg-gray-800 hover:bg-gray-700 border border-gray-700 px-4 py-2 rounded text-xs uppercase transition-colors"
                >
                  Probe
                </button>
              </div>
            </div>
            {driveInfo && (
              <div className="mt-2 text-xs bg-[#0d1117] p-2 rounded border border-gray-800 grid grid-cols-2 gap-2 text-gray-400">
                <p>SN: <span className="text-white">{driveInfo.serial_number}</span></p>
                <p>FW: <span className="text-white">{driveInfo.firmware_revision}</span></p>
                <p>Type: <span className={driveInfo.is_rotational ? "text-yellow-400" : "text-green-400"}>
                  {driveInfo.is_rotational ? "HDD (Rotational)" : "SSD/NVMe (Solid State)"}
                </span></p>
              </div>
            )}
          </div>

          <hr className="border-gray-800 my-6" />

          <h2 className="text-sm uppercase tracking-widest text-red-500 font-bold mb-4">Sanitization Directives</h2>
          
          <div className="mb-4">
            <input 
              type="text" 
              value={fileTarget}
              onChange={(e) => setFileTarget(e.target.value)}
              placeholder="Target File Path (e.g. evidence.pdf)"
              className="w-full bg-[#0d1117] border border-gray-700 rounded px-3 py-2 text-white text-sm focus:border-red-500 focus:ring-1 focus:ring-red-500 outline-none transition-all"
            />
          </div>

          <div className="mb-6">
            <select 
              value={wipeProfile}
              onChange={(e) => setWipeProfile(e.target.value)}
              className="w-full bg-[#0d1117] border border-gray-700 rounded px-3 py-2 text-white text-sm focus:border-cyan-500 outline-none"
            >
              <option value="nist_clear">NIST 800-88 Clear (Single Pass 0x00)</option>
              <option value="dod_3pass">DoD 5220.22-M (3-Pass Wipe)</option>
              <option value="hardware_purge">Hardware Purge (NVMe BLKDISCARD)</option>
            </select>
          </div>

          <div className="grid grid-cols-2 gap-3 mb-4">
            <button 
              onClick={handleRecover}
              disabled={isProcessing}
              className="col-span-2 bg-gradient-to-r from-cyan-900 to-blue-900 hover:from-cyan-800 hover:to-blue-800 border border-cyan-800 disabled:opacity-50 text-cyan-100 py-2 rounded text-sm uppercase tracking-widest font-bold transition-all"
            >
              Execute Carver (64MB Sliding)
            </button>
            <button 
              onClick={handleClone}
              disabled={isProcessing}
              className="col-span-2 bg-gradient-to-r from-purple-900 to-indigo-900 hover:from-purple-800 hover:to-indigo-800 border border-purple-800 disabled:opacity-50 text-purple-100 py-2 rounded text-sm uppercase tracking-widest font-bold transition-all"
            >
              Create Forensic Image (.DD)
            </button>
            <button 
              onClick={handleDriveWipe}
              disabled={isProcessing}
              className="bg-red-900/50 hover:bg-red-800/80 border border-red-800 disabled:opacity-50 text-red-200 py-2 rounded text-xs uppercase tracking-widest transition-all"
            >
              Wipe Drive
            </button>
            <button 
              onClick={handleFileWipe}
              disabled={isProcessing || !fileTarget}
              className="bg-orange-900/50 hover:bg-orange-800/80 border border-orange-800 disabled:opacity-50 text-orange-200 py-2 rounded text-xs uppercase tracking-widest transition-all"
            >
              Shred File
            </button>
          </div>

          <button 
            onClick={handleOpenFolder}
            className="w-full bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-300 py-2 rounded text-xs uppercase tracking-widest transition-all mb-4"
          >
            Open Evidence Folder
          </button>

          {isProcessing && (
            <div className="mt-4 w-full bg-gray-900 rounded-full h-1.5 overflow-hidden">
              <div className="bg-cyan-500 h-1.5 rounded-full animate-pulse w-full"></div>
            </div>
          )}

          {statusMsg && (
            <div className="mt-4 p-3 bg-black/50 border-l-2 border-cyan-500 text-xs text-cyan-400">
              {statusMsg}
            </div>
          )}
        </div>

        {/* Audit Trail Panel */}
        <div className="md:col-span-7 bg-[#161b22] p-6 rounded-lg border border-gray-800 shadow-2xl flex flex-col h-[500px]">
          <h2 className="text-sm uppercase tracking-widest text-emerald-500 font-bold mb-4 flex items-center justify-between">
            <span>Merkle Audit Chain</span>
            <span className="text-[10px] text-gray-500 font-normal border border-gray-700 px-2 py-0.5 rounded">SHA-256</span>
          </h2>
          <div className="flex-1 overflow-y-auto pr-2 space-y-2">
            {auditTrail.length === 0 ? (
              <p className="text-gray-600 italic text-xs">Awaiting genesis block...</p>
            ) : (
              auditTrail.map((entry) => (
                <div key={entry.index} className="bg-[#0d1117] p-3 rounded border border-gray-800 text-[11px] font-mono leading-tight">
                  <div className="flex justify-between text-gray-400 mb-1">
                    <span>
                      <span className="text-emerald-500 mr-2">[{entry.index}]</span>
                      <span className="text-gray-300">OP_{entry.action}</span> 
                      <span className="ml-2 text-gray-500">{entry.target}</span>
                    </span>
                    <span className={entry.status.includes('SUCCESS') || entry.status.includes('CLEAN') ? 'text-green-500' : 'text-red-500'}>
                      {entry.status}
                    </span>
                  </div>
                  <div className="text-gray-600 truncate">
                    PREV: <span className="text-gray-500">{entry.previous_hash}</span>
                  </div>
                  <div className="text-emerald-700 truncate">
                    HASH: <span className="text-emerald-500 font-bold">{entry.record_hash}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Carved Gallery Panel */}
        <div className="md:col-span-12 bg-[#161b22] p-6 rounded-lg border border-gray-800 shadow-2xl">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-sm uppercase tracking-widest text-purple-500 font-bold">Extracted Artifacts & Intel</h2>
            <button 
              onClick={handleGeneratePdf}
              disabled={artifacts.length === 0}
              className="bg-purple-900/50 hover:bg-purple-800/80 border border-purple-800 disabled:opacity-50 text-purple-200 px-4 py-1.5 rounded text-xs uppercase tracking-widest transition-all"
            >
              Export Case Report (PDF)
            </button>
          </div>
          
          {hexViewData && (
            <div className="mb-6 p-4 bg-black border border-cyan-800 rounded relative">
              <button 
                onClick={() => setHexViewData(null)}
                className="absolute top-2 right-2 text-gray-500 hover:text-white text-xs"
              >
                Close [X]
              </button>
              <h3 className="text-xs text-cyan-500 mb-2 font-bold uppercase">Raw Byte Inspection (First 256 B)</h3>
              <pre className="text-[10px] text-gray-400 font-mono whitespace-pre">{hexViewData}</pre>
            </div>
          )}

          {artifacts.length === 0 ? (
            <div className="text-center py-16 text-gray-600 italic border border-dashed border-gray-800 rounded bg-[#0d1117]">
              No evidence extracted in current session.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {artifacts.map((art, idx) => (
                <div key={idx} className={`p-4 rounded border transition-colors group ${art.threat_tags.length > 0 ? 'bg-red-950/20 border-red-900/50 hover:border-red-500/50' : 'bg-[#0d1117] border-gray-800 hover:border-gray-600'}`}>
                  <div className="flex justify-between items-start mb-3">
                    <div>
                      <div className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                        {art.file_type}
                        {art.threat_tags.map(t => (
                          <span key={t} className="bg-red-900 text-red-200 text-[9px] px-1.5 py-0.5 rounded border border-red-700">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div className={`text-[10px] px-2 py-0.5 rounded border ${art.confidence_score > 0.8 ? 'border-green-800 text-green-400 bg-green-900/20' : 'border-yellow-800 text-yellow-400 bg-yellow-900/20'}`}>
                      {(art.confidence_score * 100).toFixed(0)}% CONF
                    </div>
                  </div>
                  
                  {art.file_type === "REGEX_HARVEST_DATA" ? (
                    <div className="text-[10px] text-gray-400 h-24 overflow-y-auto border border-gray-800 p-2 bg-black rounded">
                      {art.regex_strings.map((str, i) => (
                        <div key={i} className="text-purple-400 break-all mb-1">{str}</div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-[11px] text-gray-500 space-y-1.5">
                      <div className="flex justify-between">
                        <span>Offset:</span>
                        <span className="text-cyan-600 font-bold">0x{art.start_offset.toString(16).toUpperCase()}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span>Size:</span>
                        <span className="text-gray-300">{art.size_bytes} B</span>
                      </div>
                      <div className="flex justify-between border-t border-gray-800 pt-1 mt-1 items-center">
                        <span className="truncate mr-2" title={art.sha256_checksum}>
                          SHA256: <span className="text-gray-400">{art.sha256_checksum.substring(0, 16)}...</span>
                        </span>
                        <button 
                          onClick={() => handleHexView(art.output_path)}
                          className="text-[9px] bg-gray-800 hover:bg-gray-700 px-2 py-1 rounded border border-gray-700 uppercase"
                        >
                          Hex View
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
    </div>
  );
}

export default App;
