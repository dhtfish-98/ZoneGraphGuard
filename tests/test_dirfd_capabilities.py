"""Directory-relative I/O support must be explicit before requested opens."""
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

CONFIG = {'module': 'zone_graph_guard.files', 'function': 'Reader', 'shape': 'zone', 'error': 'safe_descriptor_reads_unavailable', 'cli': ['snapshot', '--root', 'ROOT']}
READER = importlib.import_module(CONFIG["module"])
FUNCTION = getattr(READER, CONFIG["function"])

def operation(path):
    if CONFIG["shape"] == "write":
        FUNCTION(str(path), "bounded output\n")
        return None
    if CONFIG["shape"] == "proof":
        return FUNCTION(str(path))
    if CONFIG["shape"] == "zone":
        from zone_graph_guard.contracts import Limits
        reader = FUNCTION(str(path.parent), Limits())
        try:
            return reader.read(path.name)
        finally:
            reader.close()
    return FUNCTION(str(path), 1024)

DRIVER = """import importlib,json,os,sys,shutil
config=json.loads(sys.argv[1]);main=importlib.import_module(config["module"].split(".")[0]+".cli").main
capability,mode=sys.argv[2:4]
if mode=="missing":delattr(os,capability)
else:setattr(os,capability,{"none":None,"empty":set(),"list":[os.open,os.stat],"tuple":(os.open,os.stat),"missing_open":{os.stat},"open_only":{os.open},"missing_stat":{os.open}}[mode])
raise SystemExit(main(sys.argv[4:]))
"""

class DirectoryCapabilityTests(unittest.TestCase):
    def test_invalid_declarations_refuse_before_requested_open_and_cli_is_controlled(self):
        cases=[("supports_dir_fd", mode) for mode in ("missing","none","empty","list","tuple","missing_open")]
        if CONFIG["shape"]=="write":
            cases.append(("supports_dir_fd","missing_stat"))
            cases += [("supports_follow_symlinks", mode) for mode in ("missing","none","empty","list","tuple","open_only")]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory).resolve()/"snapshot"
            if CONFIG["shape"]!="write":path.write_bytes(b"synthetic")
            original_open=os.open
            for capability,mode in cases:
                with self.subTest(capability=capability,mode=mode):
                    values={"none":None,"empty":set(),"list":[os.open,os.stat],"tuple":(os.open,os.stat),"missing_open":{os.stat},"open_only":{os.open},"missing_stat":{os.open}}
                    with patch.object(os,"open",wraps=original_open) as opened:
                        value=values.get(mode)
                        if mode=="missing_stat" or mode=="open_only":value={opened}
                        with patch.object(os,capability,value,create=True):
                            if mode=="missing":delattr(os,capability)
                            if CONFIG["shape"]=="proof":
                                result=operation(path)
                                self.assertEqual(result["status"],"OPEN")
                                self.assertEqual(result["errors"],[CONFIG["error"]])
                            else:
                                with self.assertRaises(Exception) as failure:operation(path)
                                self.assertEqual(getattr(failure.exception,"code",str(failure.exception)),CONFIG["error"])
                            opened.assert_not_called()
                    args=[str(path) if x=="PATH" else str(path.parent) if x=="ROOT" else x for x in CONFIG["cli"]]
                    process=subprocess.run([sys.executable,"-c",DRIVER,json.dumps(CONFIG),capability,mode,*args],capture_output=True,text=True,timeout=10)
                    self.assertEqual(process.returncode,2,(process.stdout,process.stderr))
                    self.assertNotIn("Traceback",process.stderr)
                    self.assertEqual(json.loads(process.stdout)["status"],"OPEN")
            if CONFIG["shape"]=="write":self.assertFalse(path.exists())
            else:self.assertEqual(path.read_bytes(),b"synthetic")

    def test_normal_frozenset_capability_retains_regular_file_behavior(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory).resolve()/"snapshot"
            if CONFIG["shape"]!="write":path.write_bytes(b"synthetic")
            with patch.object(os,"supports_dir_fd",frozenset(os.supports_dir_fd)):
                result=operation(path)
            if CONFIG["shape"]=="write":self.assertEqual(path.read_bytes(),b"bounded output\n")
            elif CONFIG["shape"]=="proof":self.assertNotIn(CONFIG["error"],result["errors"])
            else:self.assertEqual(result,b"synthetic")

if __name__=="__main__":unittest.main()
