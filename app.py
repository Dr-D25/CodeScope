import streamlit as st
import capstone
from capstone import *
import difflib, collections, math, re, os, io, hashlib, tempfile, random, json, base64, zipfile, datetime, sys, importlib, warnings
import pandas as pd
from typing import List, Dict, Tuple, Optional, Any

PE_AVAIL = ELF_AVAIL = YARA_AVAIL = GRAPHVIZ_AVAIL = PLOTLY_AVAIL = PIL_AVAIL = REQUESTS_AVAIL = AGRID_AVAIL = PDF_AVAIL = ML_AVAIL = False
try:
    import pefile; PE_AVAIL = True
except: pass
try:
    from elftools.elf.elffile import ELFFile; ELF_AVAIL = True
except: pass
try:
    import yara; YARA_AVAIL = True
except: pass
try:
    import graphviz; GRAPHVIZ_AVAIL = True
except: pass
try:
    import plotly.express as px; PLOTLY_AVAIL = True
except: pass
try:
    from PIL import Image; import numpy as np; PIL_AVAIL = True
except: pass
try:
    import requests; REQUESTS_AVAIL = True
except: pass
try:
    from streamlit_aggrid import AgGrid, GridOptionsBuilder; AGRID_AVAIL = True
except: pass
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas; PDF_AVAIL = True
except: pass
try:
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.ensemble import RandomForestClassifier; ML_AVAIL = True
except: pass

st.set_page_config(page_title="Disassembler by Dr.D25", page_icon="💀", layout="wide")
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
.stApp { background: #0a0a0a; color: #00ff41; font-family: 'Share Tech Mono', monospace; }
.glitch { font-size: 3rem; font-weight: bold; text-transform: uppercase; color: #00ff41; text-shadow: 2px 0 red, -2px 0 cyan; animation: glitch 1s infinite; }
@keyframes glitch { 0% {text-shadow: 2px 0 red, -2px 0 cyan;} 20% {text-shadow: -1px 0 lime, 1px 0 magenta;} 40% {text-shadow: 1px 0 red, -1px 0 cyan;} 60% {text-shadow: -2px 0 lime, 2px 0 magenta;} 80% {text-shadow: 2px 0 red, -2px 0 cyan;} 100% {text-shadow: -1px 0 lime, 1px 0 magenta;} }
.stButton > button { background: #1a1a1a; color: #00ff41; border: 1px solid #00ff41; }
.stButton > button:hover { background: #00ff41; color: #0a0a0a; }
.st-bd, .stDataFrame, .stExpander { background: #0d1117; border: 1px solid #ff073a; }
hr { border: 1px dashed #00ff41; }
.diff-table { background: #0a0a0a; color: #00ff41; }
.diff_header { background: #1a1a1a; color: #ff073a; }
.diff_add { background: #003300; }
.diff_sub { background: #330000; }
.diff_chg { background: #333300; }
</style>""", unsafe_allow_html=True)

# Engine
ARCH_OPTIONS = {
    "x86 32-bit": (CS_ARCH_X86, CS_MODE_32),
    "x86 64-bit": (CS_ARCH_X86, CS_MODE_64),
    "ARM":        (CS_ARCH_ARM, CS_MODE_ARM),
    "ARM64":      (CS_ARCH_ARM64, CS_MODE_ARM),
    "ARM Thumb":  (CS_ARCH_ARM, CS_MODE_THUMB),
}

def is_terminator(instr: dict) -> bool:
    term = {CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_IRET}
    return bool(set(instr.get("groups", [])) & term)

def disassemble(data, arch, mode, base):
    md = capstone.Cs(arch, mode)
    md.detail = True
    return [{"address": i.address, "size": i.size, "bytes": i.bytes,
             "mnemonic": i.mnemonic, "op_str": i.op_str,
             "groups": list(i.groups)} for i in md.disasm(data, base)]

def group_into_blocks(insns):
    blocks, cur = [], []
    for insn in insns:
        cur.append(insn)
        if is_terminator(insn):
            blocks.append(cur)
            cur = []
    if cur: blocks.append(cur)
    return blocks

def block_to_text(blk): return "\n".join(f"0x{i['address']:08x}: {i['mnemonic']} {i['op_str']}".strip() for i in blk)
def block_addr_range(blk):
    s = blk[0]["address"]; e = blk[-1]["address"] + blk[-1]["size"] - 1
    return f"0x{s:08x} - 0x{e:08x}"

# Comparison
def compare_blocks(blocks1, blocks2, threshold):
    str1 = [block_to_text(b) for b in blocks1]
    str2 = [block_to_text(b) for b in blocks2]
    recs = []
    for i, s1 in enumerate(str1):
        for j, s2 in enumerate(str2):
            sim = difflib.SequenceMatcher(None, s1, s2).ratio()
            if sim >= threshold:
                recs.append({"Index A": i, "Block A": block_addr_range(blocks1[i]),
                             "Index B": j, "Block B": block_addr_range(blocks2[j]),
                             "Similarity": round(sim,4), "Status": "Identical" if sim==1 else "Similar"})
    df = pd.DataFrame(recs)
    if not df.empty: df = df.sort_values("Similarity", ascending=False).reset_index(drop=True)
    return df

# All features 
def entropy_scan(data, w=256):
    if not data: return pd.DataFrame()
    res = []
    for i in range(0, len(data), w):
        chunk = data[i:i+w]; cnt = collections.Counter(chunk)
        L = len(chunk); ent = -sum((c/L)*math.log2(c/L) for c in cnt.values())
        res.append({"offset": i, "entropy": round(ent,4)})
    return pd.DataFrame(res)

def extract_strings(data, min_len=4):
    a = re.compile(rb'[ -~]{%d,}'%min_len); w = re.compile(rb'(?:[\x20-\x7E]\x00){%d,}'%min_len)
    out = []
    for m in a.finditer(data): out.append({"offset": m.start(), "string": m.group().decode('ascii','ignore')})
    for m in w.finditer(data):
        try: out.append({"offset": m.start(), "string": m.group().decode('utf-16-le','ignore')})
        except: pass
    return out

def instruction_stats(insns):
    cnt = collections.Counter(i["mnemonic"] for i in insns)
    df = pd.DataFrame(cnt.most_common(30), columns=["Mnemonic","Count"])
    df["Count"] = df["Count"].astype(int)
    total = len(insns) if insns else 1
    df["%"] = (df["Count"]/total*100).round(2)
    return df

def obfuscation_detect(insns):
    tricks = []
    for i in range(len(insns)-1):
        if insns[i]["mnemonic"]=="push" and insns[i+1]["mnemonic"]=="ret":
            tricks.append(f"push/ret at 0x{insns[i]['address']:x}")
    short = [i for i in insns if i["mnemonic"].startswith("j") and i["size"]<4]
    if len(short)>5: tricks.append("Many short jumps")
    nop_cnt = sum(1 for i in insns if i["mnemonic"]=="nop")
    if nop_cnt>10: tricks.append(f"Excessive NOPs ({nop_cnt})")
    return {"tricks": tricks, "score": min(len(tricks),10)}

def ransomware_heuristics(data, insns):
    ind = []
    for s in [b"CryptEncrypt",b"RSA",b"AES"]:
        if s in data: ind.append(f"API: {s.decode()}")
    for p in [b"YOUR FILES",b"decrypt",b"bitcoin"]:
        if p.lower() in data.lower(): ind.append(f"Note: {p.decode()}")
    xor_cnt = sum(1 for i in insns if i["mnemonic"]=="xor" and "ptr" in i["op_str"])
    if xor_cnt>20: ind.append("Many XOR (cipher)")
    return {"ransom_score": len(ind), "indicators": ind}

def injection_detect(insns):
    pat = []; seq = " ".join(i["mnemonic"] for i in insns)
    if "push ret" in seq: pat.append("push/ret")
    calls = {i["op_str"] for i in insns if i["mnemonic"]=="call"}
    if any("VirtualAlloc" in c or "VirtualProtect" in c for c in calls): pat.append("Memory API")
    return {"inj_score": len(pat), "patterns": pat}

def heatmap_img(data, width=64):
    if not PIL_AVAIL: return None
    df = entropy_scan(data)
    if df.empty: return None
    maxe = df["entropy"].max()
    pixels = [(0,int(255*r["entropy"]/maxe),0) if maxe else (0,0,0) for _,r in df.iterrows()]
    h = (len(pixels)+width-1)//width
    img = Image.new('RGB',(width,h),(10,10,10))
    for i,pix in enumerate(pixels):
        x=i%width; y=i//width
        if y<h: img.putpixel((x,y),pix)
    buf = io.BytesIO(); img.save(buf, format='PNG'); return buf.getvalue()

def call_graph(insns, func_starts=None, highlight_funcs=False):
    if not GRAPHVIZ_AVAIL: return None
    dot = graphviz.Digraph(comment='Call Graph', format='png',
                           node_attr={'shape': 'box', 'style': 'filled',
                                      'fontcolor': '#00ff41', 'fontname': 'Courier New'})
    func_blocks = collections.defaultdict(list)
    current_start = None
    for insn in insns:
        if func_starts and insn["address"] in func_starts:
            current_start = insn["address"]
        if current_start is not None:
            func_blocks[current_start].append(insn)
    for addr, block in func_blocks.items():
        label = f"func_{addr:#x}\n{block[0]['mnemonic']}"
        if highlight_funcs and addr in func_starts:
            fillcolor = '#ff8c00'
        else:
            fillcolor = '#0d1117'
        dot.node(str(addr), label=label, fillcolor=fillcolor)
    for insn in insns:
        if insn["mnemonic"] == "call":
            try:
                target = int(insn["op_str"], 16)
                if target in func_blocks:
                    dot.edge(str(insn["address"]), str(target))
            except:
                pass
    return dot

    
def bindiff_plus(blk1, blk2):
    def norm(insn):
        o = re.sub(r'0x[a-fA-F0-9]+','imm', insn["op_str"])
        o = re.sub(r'\b([er]?[abcd]x|r\d+[wd]?|rip|rbp|rsp|rdi|rsi|eax|ebx|ecx|edx|esp|ebp|esi|edi|ax|bx|cx|dx)\b','reg',o,flags=re.I)
        return insn["mnemonic"]+" "+o
    n1=["\n".join(norm(i) for i in b) for b in blk1]
    n2=["\n".join(norm(i) for i in b) for b in blk2]
    matches=[]
    for i,s1 in enumerate(n1):
        best_j,best_s=-1,0
        for j,s2 in enumerate(n2):
            sim=difflib.SequenceMatcher(None,s1,s2).ratio()
            if sim>best_s: best_s,best_j=sim,j
        if best_s>=0.8: matches.append((i,best_j,best_s))
    return matches

def batch_scan(files, arch, mode, base):
    rows=[]
    for name,data in files:
        insns=disassemble(data,arch,mode,base); blks=group_into_blocks(insns)
        rows.append({"name":name,"blocks":len(blks),"instructions":len(insns)})
    return pd.DataFrame(rows)

def generate_yara_rule(blocks, fname="sample"):
    rule = f"rule auto_{fname} {{\n  strings:\n"
    for i,blk in enumerate(blocks[:20]):
        hx = ''.join(f'{b:02x}' for insn in blk for b in insn["bytes"])
        if len(hx)>=16: rule += f'    $blk_{i} = {{ {hx[:64]} }}\n'
    rule += "  condition:\n    any of them\n}"
    return rule

def vt_lookup(file_hash):
    if not REQUESTS_AVAIL: return "requests missing"
    api = st.secrets.get("vt_api_key","")
    if not api: return "No VirusTotal API key set"
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers={"x-apikey":api})
        return r.json() if r.status_code==200 else f"Error {r.status_code}"
    except Exception as e: return str(e)

def send_alert(msg, url):
    if not REQUESTS_AVAIL: return "requests missing"
    try: requests.post(url, json={"content":msg}); return "Sent"
    except Exception as e: return str(e)

def hex_viewer(data):
    dump=""
    for i in range(0,len(data),16):
        chunk=data[i:i+16]; hex_part=' '.join(f'{b:02x}' for b in chunk)
        asc=''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        dump+=f"{i:08x}: {hex_part:<48} |{asc}|\n"
    return dump

def patch_bytes(data, off, new):
    d=bytearray(data)
    for i,b in enumerate(new):
        if off+i<len(d): d[off+i]=b
    return bytes(d)

def gen_ida_script(blks):
    s="""# IDA script generated by VX God Mode
import idc, idaapi
def add_comments():
"""
    for i,blk in enumerate(blks):
        for insn in blk: s+=f'    idc.set_cmt({insn["address"]}, "Block {i}", 0)\n'
    s+="add_comments()\n"
    return s

def gen_dossier(name, data, blks, insns):
    d=f"DOSSIER: {name}\n{'='*40}\n"
    d+=f"SHA256: {hashlib.sha256(data).hexdigest()}\nSize: {len(data)} bytes\n"
    d+=f"Blocks: {len(blks)}\nInsns: {len(insns)}\n"
    d+=f"Code name: VX-{random.choice(['Kraken','Cerberus','Spectre'])}-{hashlib.md5(data).hexdigest()[:6].upper()}\n"
    return d

def anti_debug_detect(insns):
    suspects=[]
    anti={'rdtsc','cpuid','int 2d','sysenter'}
    for insn in insns:
        if insn["mnemonic"] in anti: suspects.append(f"{insn['mnemonic']} at 0x{insn['address']:x}")
        if "fs:" in insn["op_str"] and "0x30" in insn["op_str"]: suspects.append("FS:[0x30] PEB.BeingDebugged")
    return suspects

def steganography_detect(data, pe=None):
    hints=[]
    if pe:
        try:
            overlay = pe.get_overlay()
            if overlay:
                ent = entropy_scan(overlay)["entropy"].mean()
                if ent>6.0: hints.append(f"Overlay with high entropy ({ent:.2f})")
        except: pass
    return hints

def perceptual_block_hash(blk):
    norm=" ".join(re.sub(r'0x[a-fA-F0-9]+','imm',
                 re.sub(r'\b([er]?[abcd]x|r\d+[wd]?|rip|rbp|rsp|rdi|rsi|eax|ebx|ecx|edx|esp|ebp|esi|edi|ax|bx|cx|dx)\b','reg',
                 f"{i['mnemonic']} {i['op_str']}", flags=re.I)) for i in blk)
    return hashlib.md5(norm.encode()).hexdigest()

def structural_diff(blocks1, blocks2):
    def build_adj(blocks):
        adj=collections.defaultdict(set)
        for i,blk in enumerate(blocks):
            last=blk[-1]
            if CS_GRP_JUMP in last["groups"]:
                try:
                    tgt=int(last["op_str"],16)
                    for j,b in enumerate(blocks):
                        if b[0]["address"]==tgt: adj[i].add(j)
                except: pass
        return adj
    adj1=build_adj(blocks1); adj2=build_adj(blocks2)
    size_diff=abs(len(blocks1)-len(blocks2))
    common_edges=0
    for src,dsts in adj1.items():
        for dst in dsts:
            if src in adj2 and dst in adj2[src]: common_edges+=1
    return {"size_diff": size_diff, "common_edges": common_edges}

def version_timeline(file_data_list):
    versions=[]
    for name,data in file_data_list:
        insns=disassemble(data, CS_ARCH_X86, CS_MODE_64, 0)
        blks=group_into_blocks(insns)
        hashes=[perceptual_block_hash(b) for b in blks]
        versions.append({"name":name,"blocks":len(blks),"hashes":hashes})
    changes=[]
    for i in range(1,len(versions)):
        prev,curr=versions[i-1],versions[i]
        added=len(curr["hashes"])-len(prev["hashes"])
        common=len(set(curr["hashes"]) & set(prev["hashes"]))
        changes.append(f"{prev['name']} -> {curr['name']}: +{added} blocks, {common} common")
    return versions, changes

def train_ml_model():
    X=["push mov add","mov xor ret","call push ret","nop nop nop"]
    y=[0,1,0,1]
    vec=CountVectorizer(analyzer='word',ngram_range=(2,3))
    clf=RandomForestClassifier()
    clf.fit(vec.fit_transform(X),y)
    return vec,clf

def classify_sample(insns, vec, clf):
    text=" ".join(i["mnemonic"] for i in insns[:1000])
    proba=clf.predict_proba(vec.transform([text]))[0]
    return {"benign": proba[0], "malware": proba[1]} if len(proba)==2 else proba

def generate_pdf_report(file_name, data, blocks, insns, pe_info, elf_info):
    if not PDF_AVAIL: return None
    buf=io.BytesIO()
    c=canvas.Canvas(buf, pagesize=letter)
    c.setFillColorRGB(0,0.5,0); c.drawString(100,750,"CodeScope - Report")
    c.setFillColorRGB(0,1,0)
    y=730
    for line in [f"File: {file_name}", f"SHA256: {hashlib.sha256(data).hexdigest()}",
                 f"Size: {len(data)} bytes", f"Blocks: {len(blocks)}", f"Instructions: {len(insns)}"]:
        c.drawString(100,y,line); y-=20
    c.save(); buf.seek(0)
    return buf

ACHIEVEMENTS = {"first":"First Blood","many":"Block Party (>1000)","ransom":"Crypto Hunter","obfus":"Obfuscation Master"}

def get_entry_point(data):
    if PE_AVAIL:
        try:
            pe = pefile.PE(data=data)
            return pe.OPTIONAL_HEADER.AddressOfEntryPoint
        except: pass
    if ELF_AVAIL:
        try:
            elf = ELFFile(io.BytesIO(data))
            return elf.header['e_entry']
        except: pass
    return None

def find_entry_block(blocks, entry_va, base):
    target = base + entry_va
    for i, blk in enumerate(blocks):
        if blk[0]["address"] <= target < blk[-1]["address"] + blk[-1]["size"]:
            return i
    return None

def get_function_starts(insns):
    targets = set()
    for insn in insns:
        if insn["mnemonic"] == "call":
            try:
                tgt = int(insn["op_str"], 16)
                targets.add(tgt)
            except:
                pass
    return targets

def is_func_block(blk, func_starts):
    return blk[0]["address"] in func_starts

def build_control_flow_graph(blocks, entry_idx=None, func_starts=None):
    if not GRAPHVIZ_AVAIL: return None
    dot = graphviz.Digraph(comment='CFG', format='png',
                           node_attr={'shape': 'box', 'style': 'filled',
                                      'fontcolor': '#00ff41', 'fontname': 'Courier New'})
    for i, blk in enumerate(blocks):
        if i == entry_idx:
            fillcolor = '#ff073a'
        elif func_starts and blk[0]["address"] in func_starts:
            fillcolor = '#ff8c00'
        else:
            fillcolor = '#0d1117'
        label = f"B{i}\n{blk[0]['address']:#x}"
        dot.node(str(i), label=label, fillcolor=fillcolor)
    for i, blk in enumerate(blocks):
        last = blk[-1]
        if CS_GRP_JUMP in last["groups"]:
            try:
                target = int(last["op_str"], 16)
                for j, b in enumerate(blocks):
                    if b[0]["address"] == target:
                        dot.edge(str(i), str(j))
            except:
                pass
    return dot


def generate_ida_listing_html(insns, blocks, entry_va, func_starts, base, max_blocks=10000):
    if not insns:
        return "<p style='color:#00ff41'>No instructions</p>"

    total_blocks = len(blocks)
    shown_blocks = min(max_blocks, total_blocks)

    html_parts = [
        '<table style="width:100%; font-family: \'Share Tech Mono\', monospace; font-size:14px; '
        'border-collapse: collapse; color: #00ff41; background-color: #0a0a0a;">',
        '<tr style="background-color: #1a1a1a; color: #ff073a;">',
        '<th style="width: 10%;">Address</th>',
        '<th style="width: 25%;">Bytes</th>',
        '<th style="width: 65%;">Instruction</th>',
        '</tr>'
    ]

    for blk_idx in range(shown_blocks):
        blk = blocks[blk_idx]
        is_entry = (entry_va is not None and 
                    blk[0]["address"] <= base + entry_va < blk[-1]["address"] + blk[-1]["size"])
        is_func = blk[0]["address"] in func_starts
        entry_tag = '<span style="color:#ff073a">[ENTRY]</span>' if is_entry else ''
        func_tag = '<span style="color:#ff8c00">[FUNC]</span>' if is_func else ''
        html_parts.append(
            f'<tr style="background-color: #1f1f1f; color: #aaa;">'
            f'<td colspan="3"><b>Block {blk_idx}</b> [{block_addr_range(blk)}] {entry_tag} {func_tag}</td></tr>'
        )
        for insn in blk:
            addr_str = f"0x{insn['address']:08x}"
            bytes_str = ' '.join(f'{b:02x}' for b in insn["bytes"])
            instr_str = f"{insn['mnemonic']} {insn['op_str']}"
            if is_entry:
                bg = '#4a0000'
            elif is_func:
                bg = '#4a2a00'
            else:
                bg = '#0a0a0a'
            html_parts.append(
                f'<tr style="background-color: {bg};">'
                f'<td style="padding: 2px 8px;">{addr_str}</td>'
                f'<td style="padding: 2px 8px;">{bytes_str}</td>'
                f'<td style="padding: 2px 8px;">{instr_str}</td>'
                f'</tr>'
            )

    if total_blocks > shown_blocks:
        html_parts.append(
            f'<tr style="background-color: #1f1f1f; color: #aaa;">'
            f'<td colspan="3">... and {total_blocks - shown_blocks} more blocks</td>'
            f'</tr>'
        )
    html_parts.append('</table>')
    return '\n'.join(html_parts)


def load_code_section(data, arch, mode):
   
    if PE_AVAIL:
        try:
            pe = pefile.PE(data=data)
            entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            for section in pe.sections:
                section_start = section.VirtualAddress
                section_end = section_start + section.Misc_VirtualSize
                if section_start <= entry_rva < section_end:
                    section_data = section.get_data()
                    base_addr = pe.OPTIONAL_HEADER.ImageBase + section_start
                    return section_data, base_addr
            for section in pe.sections:
                if section.Characteristics & 0x20000000:
                    section_data = section.get_data()
                    base_addr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                    return section_data, base_addr
        except:
            pass

    if ELF_AVAIL:
        try:
            elf = ELFFile(io.BytesIO(data))
            for section in elf.iter_sections():
                if section.name == '.text':
                    section_data = section.data()
                    base_addr = section.header.sh_addr
                    return section_data, base_addr
        except:
            pass

    return data, 0


def get_pe_sections(data):
    if not PE_AVAIL:
        return {}
    try:
        pe = pefile.PE(data=data)
        sections = {}
        for sec in pe.sections:
            name = sec.Name.decode().strip('\x00')
            sections[name] = (sec.get_data(), pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress)
        return sections
    except:
        return {}

def get_elf_sections(data):
    if not ELF_AVAIL:
        return {}
    try:
        elf = ELFFile(io.BytesIO(data))
        sections = {}
        for sec in elf.iter_sections():
            if sec.name:
                sections[sec.name] = (sec.data(), sec.header.sh_addr)
        return sections
    except:
        return {}

def get_all_sections(data):
    pe_sec = get_pe_sections(data)
    if pe_sec:
        return pe_sec
    return get_elf_sections(data)

def build_function_list(blocks, func_starts):
    funcs = []
    for i, blk in enumerate(blocks):
        addr = blk[0]["address"]
        if addr in func_starts:
            funcs.append((addr, i))
    return sorted(funcs, key=lambda x: x[0])

def compare_sections(sec1_data, sec1_base, sec2_data, sec2_base, arch, mode, threshold):
    
    insns1 = disassemble(sec1_data, arch, mode, sec1_base)
    insns2 = disassemble(sec2_data, arch, mode, sec2_base)
    blk1 = group_into_blocks(insns1)
    blk2 = group_into_blocks(insns2)
    df = compare_blocks(blk1, blk2, threshold)
    return df, blk1, blk2, insns1, insns2

# Main UI 
def main():
    st.markdown('<h1 class="glitch">💀 CodeScope by Dr.D25</h1>', unsafe_allow_html=True)
    if 'achieve' not in st.session_state: st.session_state.achieve=set()
    if 'plugins' not in st.session_state: st.session_state.plugins={}

    with st.sidebar:
        arch_name = st.selectbox("Architecture", list(ARCH_OPTIONS.keys()), index=1)
        arch, mode = ARCH_OPTIONS[arch_name]
        base = st.number_input("Base address (hex)", 0x0, step=0x1000, format="%x", help="Ignored for PE/ELF")
        sim_thresh = st.slider("Block similarity %", 0,100,80)/100.0
        webhook = st.text_input("Webhook URL", type="password")
        uploaded_plugin = st.file_uploader("Load plugin (.py)", type="py")
        if uploaded_plugin:
            pname=uploaded_plugin.name.replace(".py","")
            module = importlib.util.module_from_spec(importlib.util.spec_from_loader(pname, loader=None))
            exec(uploaded_plugin.getvalue().decode(), module.__dict__)
            st.session_state.plugins[pname]=module
            st.success(f"Plugin {pname} loaded")

    col1,col2=st.columns(2)
    with col1: f1=st.file_uploader("📁 First binary", type=None, key="f1")
    with col2: f2=st.file_uploader("📁 Second binary", type=None, key="f2")
    data1 = f1.read() if f1 else None
    data2 = f2.read() if f2 else None

    if data1:
        st.session_state.achieve.add("first")
        @st.cache_data(show_spinner=False)
        def get_analysis(data, arch, mode):
            code, code_base = load_code_section(data, arch, mode)
            if not code:
                st.error("Failed to extract code section")
                return [], []
            insns = disassemble(code, arch, mode, code_base)
            blocks = group_into_blocks(insns)
            return insns, blocks
        insns1,blocks1 = get_analysis(data1,arch,mode)
        if len(blocks1)>1000: st.session_state.achieve.add("many")
    else: insns1,blocks1=[],[]
    if data2: insns2,blocks2 = get_analysis(data2,arch,mode)
    else: insns2,blocks2=[],[]

    st.success(f"File1: {len(blocks1)} blocks, {len(insns1)} insns | File2: {len(blocks2)} blocks")

    tabs=st.tabs([
        "🔎 Blocks","🧬 Compare","⚗️ Entropy","📜 Strings","🏗️ PE/ELF",
        "🗺️ CFG","🦠 YARA","🧪 Signatures","📊 Stats","🕵️ Diff Asm",
        "👁️ Obfuscation","🔐 Crypto","💉 Injection","🌡️ Heatmap",
        "📊 3D Entropy","🕸️ Call Graph","🧬 BinDiff+","📂 Batch Scan",
        "🎯 YARA Block","🛡️ VirusTotal","📢 Alerts","📝 Hex Editor",
        "🧵 IDA Script","👤 Dossier","🏆 Achievements",
        "🛡️ Anti-Debug","🥷 Stego","🌐 Interactive CFG","📏 Structural Diff",
        "🔑 Perceptual Hash","⏳ Version Timeline","📄 PDF Report",
        "🧠 ML Classify","🧩 Plugins","🔧 Block Patcher"
    ])

    def pick_file(key):
        ch=st.radio("File",[1,2],key=key,horizontal=True)
        if ch==1 and data1: return data1,blocks1,insns1
        elif ch==2 and data2: return data2,blocks2,insns2
        return None,[],[]

    # 0 Blocks
    with tabs[0]:
        st.subheader("Disassembly Listing (IDA View)")
        entry1 = get_entry_point(data1) if data1 else None
        entry2 = get_entry_point(data2) if data2 else None
        func_starts1 = get_function_starts(insns1) if insns1 else set()
        func_starts2 = get_function_starts(insns2) if insns2 else set()

        file_choice = st.radio("File", [1, 2], horizontal=True, key="listing_file")
        if file_choice == 1 and data1:
            insns, blks, entry_va, func_set = insns1, blocks1, entry1, func_starts1
        elif file_choice == 2 and data2:
            insns, blks, entry_va, func_set = insns2, blocks2, entry2, func_starts2
        else:
            st.info("No file selected")
            insns, blks, entry_va, func_set = [], [], None, set()

        if insns:
            html = generate_ida_listing_html(insns, blks, entry_va, func_set, base)
            st.components.v1.html(html, height=700, scrolling=True)
          
    # 1 Compare
    with tabs[1]:
        st.subheader("Block Comparison (BinDiff-style)")
        if not (data1 and data2):
            st.info("Load two binaries to compare")
            st.stop()

        # Выбор секций
        sec1_dict = get_all_sections(data1)
        sec2_dict = get_all_sections(data2)
        if sec1_dict and sec2_dict:
            colA, colB = st.columns(2)
            with colA:
                sec1_name = st.selectbox("Section (File1)", list(sec1_dict.keys()), key="cmp_sec1")
                sec1_data, sec1_base = sec1_dict[sec1_name]
            with colB:
                sec2_name = st.selectbox("Section (File2)", list(sec2_dict.keys()), key="cmp_sec2")
                sec2_data, sec2_base = sec2_dict[sec2_name]
        else:
            sec1_data, sec1_base = data1, base
            sec2_data, sec2_base = data2, base

        # Сравнение
        with st.spinner("Comparing blocks..."):
            df, blk1, blk2, insns1_local, insns2_local = compare_sections(
                sec1_data, sec1_base, sec2_data, sec2_base, arch, mode, sim_thresh
            )

        if df.empty:
            st.warning("No similar blocks found with current threshold")
        else:
            # Сводка
            total1, total2 = len(blk1), len(blk2)
            identical = len(df[df["Status"] == "Identical"])
            similar = len(df[df["Status"] == "Similar"])
            st.metric("Total blocks (File1)", total1)
            st.metric("Total blocks (File2)", total2)
            col1, col2 = st.columns(2)
            col1.metric("Identical blocks", identical)
            col2.metric("Similar blocks", similar)

            # Раскрашенная таблица
            def color_status(val):
                if val == "Identical":
                    return 'background-color: #003300; color: #00ff41'
                elif val == "Similar":
                    return 'background-color: #333300; color: #ffcc00'
                return ''
            styled_df = df[["Block A", "Block B", "Similarity", "Status"]].style.applymap(
                color_status, subset=['Status']
            )
            st.dataframe(styled_df, use_container_width=True)

            # Детальный просмотр
            st.markdown("### Side-by-side view")
            sel = st.selectbox("Select match", df.index, format_func=lambda x: f"#{x}  A:{df.iloc[x]['Block A']} ↔ B:{df.iloc[x]['Block B']}  ({df.iloc[x]['Similarity']*100:.1f}%)")
            if sel is not None:
                i1, i2 = df.iloc[sel]["Index A"], df.iloc[sel]["Index B"]
                col_left, col_right = st.columns(2)
                with col_left:
                    st.markdown("**File1 block**")
                    st.code(block_to_text(blk1[i1]), language="nasm")
                with col_right:
                    st.markdown("**File2 block**")
                    st.code(block_to_text(blk2[i2]), language="nasm")

                st.markdown("**Diff (contextual)**")
                diff = difflib.HtmlDiff().make_table(
                    block_to_text(blk1[i1]).splitlines(),
                    block_to_text(blk2[i2]).splitlines(),
                    context=True, numlines=5
                )
                st.components.v1.html(diff.replace("<table", '<table class="diff-table"'), height=400)

                with st.expander("Normalized comparison (BinDiff-style)"):
                    def norm_block(blk):
                        return "\n".join(
                            f"{i['mnemonic']} {re.sub(r'0x[a-fA-F0-9]+','imm', re.sub(r'\b(e?[abcd]x|r\d+[wd]?|rip|rbp|rsp|rdi|rsi|eax|ebx|ecx|edx|esp|ebp|esi|edi|ax|bx|cx|dx)\b','reg', i['op_str'], flags=re.I))}" 
                            for i in blk
                        )
                    colL, colR = st.columns(2)
                    colL.code(norm_block(blk1[i1]), language="nasm")
                    colR.code(norm_block(blk2[i2]), language="nasm")

            # Экспорт
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("Download CSV", csv, "block_comparison.csv", mime="text/csv")

            # Визуализация на графах (опционально)
            if GRAPHVIZ_AVAIL and st.checkbox("Show CFG with highlighted matches"):
                highlight1 = set(df["Index A"].values)
                highlight2 = set(df["Index B"].values)

                def build_highlighted_cfg(blks, highlight_set, title):
                    dot = graphviz.Digraph(comment=title)
                    for i, blk in enumerate(blks):
                        fillcolor = '#ff073a' if i in highlight_set else '#0d1117'
                        dot.node(str(i), label=f"B{i}\n{blk[0]['address']:#x}",
                                 shape='box', style='filled', fillcolor=fillcolor, fontcolor='#00ff41')
                    for i, blk in enumerate(blks):
                        last = blk[-1]
                        if CS_GRP_JUMP in last["groups"]:
                            try:
                                target = int(last["op_str"], 16)
                                for j, b in enumerate(blks):
                                    if b[0]["address"] == target:
                                        dot.edge(str(i), str(j))
                            except:
                                pass
                    return dot

                colG1, colG2 = st.columns(2)
                with colG1:
                    st.markdown("**File1 CFG (red = match)**")
                    st.graphviz_chart(build_highlighted_cfg(blk1, highlight1, "File1").source)
                with colG2:
                    st.markdown("**File2 CFG (red = match)**")
                    st.graphviz_chart(build_highlighted_cfg(blk2, highlight2, "File2").source)
                  
    # 2 Entropy
    with tabs[2]:
        st.subheader("Entropy Analysis")
        if not (data1 or data2):
            st.info("Load at least one file")
            st.stop()

        col_set, col_stats = st.columns([3, 1])
        with col_set:
            window = st.slider("Window size (bytes)", 64, 4096, 256, step=64, key="ent_win")
            threshold = st.slider("High-entropy threshold", 6.0, 8.0, 7.0, step=0.1, key="ent_thresh")
        with col_stats:
            show_compare = st.checkbox("Compare files", value=False, disabled=not (data1 and data2))

        def entropy_plot(data, label, color='#00ff41'):
            df = entropy_scan(data, window)
            if df.empty:
                return None, pd.DataFrame()
            df['high'] = df['entropy'] > threshold
            return df, df.describe()

        if show_compare and data1 and data2:
            df1, stat1 = entropy_plot(data1, "File1", '#00ff41')
            df2, stat2 = entropy_plot(data2, "File2", '#ff8c00')
            if PLOTLY_AVAIL:
                import plotly.graph_objects as go
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=df1['offset'], y=df1['entropy'], mode='lines',
                                         line=dict(color='#00ff41'), name='File1'))
                high1 = df1[df1['high']]
                if not high1.empty:
                    fig.add_trace(go.Scatter(x=high1['offset'], y=high1['entropy'], mode='markers',
                                             marker=dict(color='#ff073a', size=4), name='File1 high'))
                fig.add_trace(go.Scatter(x=df2['offset'], y=df2['entropy'], mode='lines',
                                         line=dict(color='#ff8c00'), name='File2'))
                high2 = df2[df2['high']]
                if not high2.empty:
                    fig.add_trace(go.Scatter(x=high2['offset'], y=high2['entropy'], mode='markers',
                                             marker=dict(color='#ffaa00', size=4), name='File2 high'))
                fig.add_hline(y=threshold, line_dash="dash", line_color="red", annotation_text=f"Threshold {threshold}")
                fig.update_layout(template='plotly_dark', paper_bgcolor='#0a0a0a', plot_bgcolor='#0a0a0a')
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.line_chart(df1.set_index('offset')['entropy'])
                st.line_chart(df2.set_index('offset')['entropy'])
            c1, c2 = st.columns(2)
            c1.metric("File1 high‑entropy zones", df1['high'].sum())
            c2.metric("File2 high‑entropy zones", df2['high'].sum())
        else:
            d, _, _ = pick_file("ent")
            if d:
                df, stat = entropy_plot(d, "File", '#00ff41')
                if PLOTLY_AVAIL:
                    import plotly.graph_objects as go
                    fig = go.Figure()
                    fig.add_trace(go.Scatter(x=df['offset'], y=df['entropy'], mode='lines',
                                             line=dict(color='#00ff41'), name='Entropy'))
                    high = df[df['high']]
                    if not high.empty:
                        fig.add_trace(go.Scatter(x=high['offset'], y=high['entropy'], mode='markers',
                                                 marker=dict(color='#ff073a', size=4), name='High entropy'))
                    fig.add_hline(y=threshold, line_dash="dash", line_color="red",
                                  annotation_text=f"Threshold {threshold}")
                    fig.update_layout(template='plotly_dark', paper_bgcolor='#0a0a0a', plot_bgcolor='#0a0a0a')
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.line_chart(df.set_index('offset')['entropy'])
                col_m1, col_m2, col_m3 = st.columns(3)
                col_m1.metric("Mean entropy", f"{df['entropy'].mean():.3f}")
                col_m2.metric("High‑entropy windows", df['high'].sum())
                col_m3.metric("Max entropy", f"{df['entropy'].max():.3f}")
                if df['high'].any():
                    with st.expander("Suspicious regions (high entropy)"):
                        high_regions = df[df['high']][['offset', 'entropy']]
                        st.dataframe(high_regions, use_container_width=True)
                csv = df.to_csv(index=False).encode('utf-8')
                st.download_button("Download CSV", csv, "entropy.csv", mime="text/csv")
   
  # 3 Strings
    with tabs[3]:
        d,_,_=pick_file("str")
        if d:
            ml=st.slider("Min length",4,20,6)
            strs=extract_strings(d,ml); st.metric("Count",len(strs))
            st.dataframe(pd.DataFrame(strs)[:500])
   
  # 4 PE/ELF
    with tabs[4]:
        st.subheader("PE / ELF Inspector")
        if not (data1 or data2):
            st.info("Load at least one file")
            st.stop()

        # Выбор файла 
        file_choice = st.radio("File", [1, 2], horizontal=True, key="pe_elf_file")
        d = data1 if file_choice == 1 else data2
        if not d:
            st.info("No file selected")
            st.stop()

        # Анализ PE 
        pe = None
        if PE_AVAIL:
            try:
                pe = pefile.PE(data=d)
            except:
                pass

        # Анализ ELF 
        elf = None
        if ELF_AVAIL:
            try:
                elf = ELFFile(io.BytesIO(d))
            except:
                pass

        if pe:
            st.markdown("### 🏗️ PE File Analysis")
            # Основная информация
            col1, col2, col3 = st.columns(3)
            col1.metric("Machine", hex(pe.FILE_HEADER.Machine))
            col2.metric("Entry Point", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
            col3.metric("Image Base", hex(pe.OPTIONAL_HEADER.ImageBase))

            # Секции
            st.markdown("#### Sections")
            sec_data = []
            for sec in pe.sections:
                name = sec.Name.decode().strip('\x00')
                entropy = entropy_scan(sec.get_data())['entropy'].mean() if len(sec.get_data()) > 0 else 0
                sec_data.append({
                    "Name": name,
                    "Virtual Address": hex(sec.VirtualAddress),
                    "Virtual Size": hex(sec.Misc_VirtualSize),
                    "Raw Size": hex(sec.SizeOfRawData),
                    "Entropy": round(entropy, 3),
                    "Characteristics": hex(sec.Characteristics)
                })
            df_sec = pd.DataFrame(sec_data)
            st.dataframe(df_sec, use_container_width=True)

            # Импорты
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                st.markdown("#### Imports")
                import_data = []
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode() if entry.dll else ""
                    for imp in entry.imports:
                        func = imp.name.decode() if imp.name else f"ord({imp.ordinal})"
                        import_data.append({"DLL": dll, "Function": func})
                if import_data:
                    st.dataframe(pd.DataFrame(import_data), use_container_width=True, height=300)
                else:
                    st.info("No imports found")

            # Экспорты
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                st.markdown("#### Exports")
                export_data = []
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    export_data.append({
                        "Name": exp.name.decode() if exp.name else "",
                        "Ordinal": exp.ordinal,
                        "Address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)
                    })
                if export_data:
                    st.dataframe(pd.DataFrame(export_data), use_container_width=True, height=200)
                else:
                    st.info("No exports")

            # Цифровая подпись
            try:
                cert = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
                if cert.Size > 0:
                    st.success("Digital signature present")
                else:
                    st.warning("No digital signature")
            except:
                st.info("Digital signature check skipped")

        elif elf:
            st.markdown("### 🐧 ELF File Analysis")
            col1, col2, col3 = st.columns(3)
            col1.metric("Machine", str(elf.header['e_machine']))
            col2.metric("Entry Point", hex(elf.header['e_entry']))
            col3.metric("Type", elf.header['e_type'])

            # Секции
            st.markdown("#### Sections")
            sec_data = []
            for sec in elf.iter_sections():
                if sec.name:
                    entropy = entropy_scan(sec.data())['entropy'].mean() if len(sec.data()) > 0 else 0
                    sec_data.append({
                        "Name": sec.name,
                        "Address": hex(sec.header.sh_addr),
                        "Size": sec.header.sh_size,
                        "Entropy": round(entropy, 3),
                        "Type": sec.header.sh_type
                    })
            if sec_data:
                st.dataframe(pd.DataFrame(sec_data), use_container_width=True)
            else:
                st.info("No sections")

            # Сегменты
            st.markdown("#### Segments")
            seg_data = []
            for seg in elf.iter_segments():
                seg_data.append({
                    "Type": seg['p_type'],
                    "Virtual Address": hex(seg['p_vaddr']),
                    "File Size": seg['p_filesz'],
                    "Mem Size": seg['p_memsz']
                })
            if seg_data:
                st.dataframe(pd.DataFrame(seg_data), use_container_width=True)

        else:
            st.info("Not a recognized PE or ELF file")

        if data1 and data2:
            st.markdown("---")
            st.markdown("### ⚖️ Quick Compare (PE/ELF)")
            colA, colB = st.columns(2)
            with colA:
                if pe:
                    st.success("File 1 is PE")
                elif elf:
                    st.success("File 1 is ELF")
                else:
                    st.warning("File 1 unknown format")
            with colB:
                pe2 = elf2 = None
                try:
                    pe2 = pefile.PE(data=data2) if PE_AVAIL else None
                except:
                    pass
                try:
                    elf2 = ELFFile(io.BytesIO(data2)) if ELF_AVAIL else None
                except:
                    pass
                if pe2:
                    st.success("File 2 is PE")
                elif elf2:
                    st.success("File 2 is ELF")
                else:
                    st.warning("File 2 unknown format")

            if pe and pe2 and hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') and hasattr(pe2, 'DIRECTORY_ENTRY_IMPORT'):
                imports1 = {f"{e.dll.decode()}:{i.name.decode() if i.name else 'ord'}" 
                            for e in pe.DIRECTORY_ENTRY_IMPORT for i in e.imports}
                imports2 = {f"{e.dll.decode()}:{i.name.decode() if i.name else 'ord'}" 
                            for e in pe2.DIRECTORY_ENTRY_IMPORT for i in e.imports}
                common = imports1 & imports2
                only1 = imports1 - imports2
                only2 = imports2 - imports1
                st.markdown("#### Import Differences")
                col_left, col_right = st.columns(2)
                col_left.metric("Only in File1", len(only1))
                col_right.metric("Only in File2", len(only2))
                if only1:
                    with st.expander(f"File1 unique imports ({len(only1)})"):
                        st.text("\n".join(sorted(only1)[:50]))
                if only2:
                    with st.expander(f"File2 unique imports ({len(only2)})"):
                        st.text("\n".join(sorted(only2)[:50]))
                      
    # 5 CFG
    with tabs[5]:
        st.subheader("Control Flow & Call Graph (Textual)")
        if not (data1 or data2):
            st.info("Load at least one binary")
            st.stop()

        file_choice = st.radio("File", [1, 2], horizontal=True, key="cfg_text_file")
        d = data1 if file_choice == 1 else data2
        if not d:
            st.info("No file selected")
            st.stop()

        sections = get_all_sections(d) if (PE_AVAIL or ELF_AVAIL) else {}
        if sections:
            sec_name = st.selectbox("Section", list(sections.keys()), key="cfg_text_section")
            sec_data, sec_base = sections[sec_name]
            insns = disassemble(sec_data, arch, mode, sec_base)
        else:
            insns = disassemble(d, arch, mode, base)
            sec_base = base

        blocks = group_into_blocks(insns)
        func_starts = get_function_starts(insns)
        entry_va = get_entry_point(d)

        view_mode = st.radio("View", ["Block Xrefs (CFG)", "Call Graph (Functions)"], horizontal=True, key="cfg_text_view")

        if view_mode == "Block Xrefs (CFG)":
            funcs = build_function_list(blocks, func_starts)
            selected_func = None
            if funcs:
                func_options = [f"0x{addr:x}" for addr, _ in funcs]
                selected_func = st.selectbox("Filter by function", ["All"] + func_options, key="cfg_func_filter")
            if selected_func and selected_func != "All":
                func_addr = int(selected_func, 16)
                filtered_blocks = []
                inside = False
                for blk in blocks:
                    if blk[0]["address"] == func_addr:
                        inside = True
                    if inside:
                        filtered_blocks.append(blk)
                        if CS_GRP_RET in blk[-1]["groups"]:
                            break
                blocks = filtered_blocks if filtered_blocks else blocks

            addr_to_idx = {blk[0]["address"]: i for i, blk in enumerate(blocks)}
            entry_idx = find_entry_block(blocks, entry_va, sec_base) if entry_va else None

            rows = []
            for i, blk in enumerate(blocks):
                blk_type = "Normal"
                if i == entry_idx:
                    blk_type = "ENTRY"
                elif blk[0]["address"] in func_starts:
                    blk_type = "FUNC"

                targets = []
                last = blk[-1]
                if CS_GRP_JUMP in last["groups"]:
                    try:
                        tgt = int(last["op_str"], 16)
                        if tgt in addr_to_idx:
                            targets.append(f"B{addr_to_idx[tgt]}")
                        else:
                            targets.append(hex(tgt))
                    except:
                        pass
                rows.append({
                    "Block": f"B{i}",
                    "Address": hex(blk[0]["address"]),
                    "Type": blk_type,
                    "Size": len(blk),
                    "Targets": ", ".join(targets) if targets else "-",
                    "First Instr": f"{blk[0]['mnemonic']} {blk[0]['op_str']}",
                })

            df = pd.DataFrame(rows)
            def color_type(val):
                if val == "ENTRY":
                    return 'background-color: #4a0000; color: #ff073a'
                elif val == "FUNC":
                    return 'background-color: #4a2a00; color: #ff8c00'
                return ''
            styled_df = df.style.applymap(color_type, subset=['Type'])
            st.dataframe(styled_df, use_container_width=True, height=600)
            st.caption("ENTRY = entry point, FUNC = function start")
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("Download CSV", csv, "cfg_xrefs.csv", mime="text/csv")

        else:
            func_blocks = collections.defaultdict(list)
            current_func = None
            for insn in insns:
                if insn["address"] in func_starts:
                    current_func = insn["address"]
                if current_func is not None:
                    func_blocks[current_func].append(insn)

            call_rows = []
            for func_addr, instrs in func_blocks.items():
                callees = set()
                for insn in instrs:
                    if insn["mnemonic"] == "call":
                        try:
                            target = int(insn["op_str"], 16)
                            if target in func_starts or True:
                                callees.add(hex(target))
                        except:
                            pass
                call_rows.append({
                    "Function": hex(func_addr),
                    "Callees": ", ".join(sorted(callees)) if callees else "-",
                    "Block count": len(group_into_blocks(instrs)),
                })

            if call_rows:
                st.dataframe(pd.DataFrame(call_rows), use_container_width=True, height=600)
                csv = pd.DataFrame(call_rows).to_csv(index=False).encode('utf-8')
                st.download_button("Download CSV", csv, "call_graph.csv", mime="text/csv")
            else:
                st.info("No direct call instructions found")
    # 6 YARA
    with tabs[6]:
        st.subheader("YARA Scanner")
        if not YARA_AVAIL:
            st.error("yara-python not installed (pip install yara-python)")
            st.stop()

        if not (data1 or data2):
            st.info("Load at least one binary")
            st.stop()

        # Правила: загрузка или редактор
        rule_source = st.radio("Rule source", ["Upload .yar files", "Write inline"], horizontal=True, key="yara_src")
        yara_rules = None
        if rule_source == "Upload .yar files":
            rule_files = st.file_uploader("Choose .yar/.yara files", type=['yar','yara'], accept_multiple_files=True, key="yara_upload")
            if rule_files:
                sources = {}
                for f in rule_files:
                    sources[f.name] = f.read().decode('utf-8')
                try:
                    yara_rules = yara.compile(sources=sources)
                except Exception as e:
                    st.error(f"Compile error: {e}")
        else:
            inline_rule = st.text_area("Write YARA rule", height=200, 
                                      value="rule example { strings: $a = \"MZ\" condition: $a }")
            if st.button("Compile inline rule", key="yara_compile_inline"):
                try:
                    yara_rules = yara.compile(source=inline_rule)
                except Exception as e:
                    st.error(f"Compile error: {e}")

        if not yara_rules:
            st.info("Provide rules to start scanning")
            st.stop()

        # Сканирование
        col_scan1, col_scan2 = st.columns(2)
        with col_scan1:
            scan1 = st.button("Scan File 1", disabled=not data1, key="yara_scan1")
        with col_scan2:
            scan2 = st.button("Scan File 2", disabled=not data2, key="yara_scan2")
        scan_both = st.button("Scan both files", disabled=not (data1 and data2), key="yara_both")

        matches1 = []
        matches2 = []
        if scan1 or scan_both:
            matches1 = yara_rules.match(data=data1)
        if scan2 or scan_both:
            matches2 = yara_rules.match(data=data2)

        # Отображение результатов
        if matches1 or matches2:
            st.success("Scan complete. Results below.")

            # Сводка
            total_matches = len(matches1) + len(matches2)
            st.metric("Total matches", total_matches)
            if total_matches == 0:
                st.info("No rules matched")
                st.stop()

            # Фильтр по файлам
            show_file = st.multiselect("Show matches for file", ["File 1", "File 2"], 
                                       default=["File 1","File 2"], key="yara_filter")
            all_matches_data = []

            if "File 1" in show_file and matches1:
                st.markdown("### File 1 matches")
                for match in matches1:
                    with st.expander(f"Rule: {match.rule} ({len(match.strings)} hits)"):
                        for s in match.strings:
                            hex_offset = hex(s[0])
                            data_snippet = data1[s[0]:s[0]+16].hex(' ')
                            st.code(f"Offset: {hex_offset}  |  Data: {data_snippet}")
                            all_matches_data.append({
                                "File": "File1",
                                "Rule": match.rule,
                                "Offset": s[0],
                                "Identifier": s[1],
                                "Data (hex)": data_snippet
                            })
                            if insns1:
                                surrounding = [i for i in insns1 if i["address"] <= s[0] < i["address"]+i["size"]]
                                if surrounding:
                                    st.text(f"Instruction: {surrounding[0]['mnemonic']} {surrounding[0]['op_str']}")

            if "File 2" in show_file and matches2:
                st.markdown("### File 2 matches")
                for match in matches2:
                    with st.expander(f"Rule: {match.rule} ({len(match.strings)} hits)"):
                        for s in match.strings:
                            hex_offset = hex(s[0])
                            data_snippet = data2[s[0]:s[0]+16].hex(' ')
                            st.code(f"Offset: {hex_offset}  |  Data: {data_snippet}")
                            all_matches_data.append({
                                "File": "File2",
                                "Rule": match.rule,
                                "Offset": s[0],
                                "Identifier": s[1],
                                "Data (hex)": data_snippet
                            })
                            if insns2:
                                surrounding = [i for i in insns2 if i["address"] <= s[0] < i["address"]+i["size"]]
                                if surrounding:
                                    st.text(f"Instruction: {surrounding[0]['mnemonic']} {surrounding[0]['op_str']}")

            if all_matches_data:
                df_matches = pd.DataFrame(all_matches_data)
                csv = df_matches.to_csv(index=False).encode('utf-8')
                st.download_button("Download matches as CSV", csv, "yara_matches.csv", mime="text/csv")
              
    # 7 Signatures
    with tabs[7]:
        _,blks,_=pick_file("sig")
        if blks:
            rule=generate_yara_rule(blks); st.code(rule,language="yara")
            st.download_button("Download",rule,"generated.yar")
          
    # 8 Stats
    with tabs[8]:
        for i,insns in enumerate([insns1,insns2]):
            st.subheader(f"File {i+1}"); st.dataframe(instruction_stats(insns))
          
    # 9 Diff Asm
    with tabs[9]:
        if data1 and data2:
            l1=[f"0x{i['address']:08x}: {i['mnemonic']} {i['op_str']}" for i in insns1]
            l2=[f"0x{i['address']:08x}: {i['mnemonic']} {i['op_str']}" for i in insns2]
            st.code("\n".join(difflib.unified_diff(l1,l2,fromfile='File1',tofile='File2')),language="diff")
          
    # 10 Obfuscation
    with tabs[10]:
        _,_,insns=pick_file("obf")
        if insns:
            res=obfuscation_detect(insns); [st.markdown(f"- {t}") for t in res["tricks"]]
            if res["tricks"]: st.session_state.achieve.add("obfus")
              
    # 11 Crypto
    with tabs[11]:
        d,_,insns=pick_file("crypto")
        if d and insns:
            res=ransomware_heuristics(d,insns); [st.markdown(f"- {i}") for i in res["indicators"]]
            if res["ransom_score"]: st.session_state.achieve.add("ransom")
              
    # 12 Injection
    with tabs[12]:
        _,_,insns=pick_file("inj")
        if insns:
            res=injection_detect(insns); [st.markdown(f"- {p}") for p in res["patterns"]]
          
    # 13 Heatmap
    with tabs[13]:
        d,_,_=pick_file("heat")
        if d:
            img=heatmap_img(d)
            if img: st.image(img, caption="Entropy heatmap")
            else: st.error("Pillow/numpy needed")
              
    # 14 3D Entropy
    with tabs[14]:
        d,_,_=pick_file("3d")
        if d and PLOTLY_AVAIL:
            df_e=entropy_scan(d); df_e["idx"]=range(len(df_e))
            fig=px.scatter_3d(df_e,x="offset",y="entropy",z="idx",color="entropy")
            st.plotly_chart(fig,use_container_width=True)
        else: st.error("plotly missing")
          
    # 15 Call Graph
    with tabs[15]:
        if GRAPHVIZ_AVAIL:
            _,_,insns=pick_file("callg"); dot=call_graph(insns)
            if dot: st.graphviz_chart(dot.source)
              
    # 16 BinDiff+
    with tabs[16]:
        if data1 and data2:
            matches=bindiff_plus(blocks1,blocks2)
            st.dataframe(pd.DataFrame(matches,columns=["Block1","Block2","Similarity"]))
          
    # 17 Batch
    with tabs[17]:
        files_up=st.file_uploader("Upload binaries", accept_multiple_files=True, key="batch")
        if files_up:
            fdata=[(f.name,f.read()) for f in files_up]
            st.dataframe(batch_scan(fdata,arch,mode,base))
          
    # 18 YARA Block
    with tabs[18]:
        if blocks1:
            sel=st.selectbox("Block",range(len(blocks1)),format_func=lambda x:f"Block {x} {block_addr_range(blocks1[x])}")
            blk=blocks1[sel]; hx=' '.join(f'{b:02x}' for insn in blk for b in insn["bytes"])
            rule=f"rule block_{sel} {{\n  strings:\n    $a = {{ {hx} }}\n  condition:\n    $a\n}}"
            st.code(rule,language="yara"); st.download_button("Download",rule,"block.yar")
    
  # 19 VT
    with tabs[19]:
        if data1:
            sha=hashlib.sha256(data1).hexdigest(); st.write(f"SHA256: {sha}")
            if st.button("Lookup"): st.json(vt_lookup(sha))
   
  # 20 Alerts
    with tabs[20]:
        if webhook:
            msg=st.text_area("Message","Analysis finished")
            if st.button("Send"): st.write(send_alert(msg,webhook))
  
  # 21 Hex Editor
    with tabs[21]:
        d,_,_=pick_file("hex")
        if d:
            st.text_area("Hex dump",hex_viewer(d),height=400)
            off=st.number_input("Offset (hex)",0,len(d)-1,0,format="%x")
            new=st.text_input("New bytes (hex)","")
            if st.button("Patch & Download"):
                try:
                    b=bytes.fromhex(new); patched=patch_bytes(d,off,b)
                    st.download_button("Download patched",patched,"patched.bin")
                except: st.error("Invalid hex")

  # 22 IDA Script
    with tabs[22]:
        _,blks,_=pick_file("ida")
        if blks: scr=gen_ida_script(blks); st.code(scr,language="python"); st.download_button("Download",scr,"ida_script.py")
 
  # 23 Dossier
    with tabs[23]:
        if data1: st.code(gen_dossier("File1",data1,blocks1,insns1))

  # 24 Achievements
    with tabs[24]:
        for k,v in ACHIEVEMENTS.items():
            if k in st.session_state.achieve: st.success(v)
            else: st.markdown(f"🔒 {v}")
 
  # 25 Anti-Debug
    with tabs[25]:
        _,_,insns=pick_file("antidbg")
        if insns:
            susp=anti_debug_detect(insns)
            if susp: [st.markdown(f"- {s}") for s in susp]
            else: st.info("No anti-debug patterns")
        else: st.info("No file")
  
  # 26 Stego
    with tabs[26]:
        d,_,_=pick_file("stego")
        if d:
            pe=None
            if PE_AVAIL:
                try: pe = pefile.PE(data=d)
                except: pass
            hints=steganography_detect(d,pe)
            if hints: [st.warning(h) for h in hints]
            else: st.success("No obvious steganography")
        else: st.info("No file")
    
  # 27 Interactive CFG
    with tabs[27]:
        if AGRID_AVAIL:
            _,blks,_=pick_file("icfg")
            if blks:
                nodes=[{"id":i,"label":block_addr_range(b),"size":len(b)} for i,b in enumerate(blks)]
                edges=[]
                for i,b in enumerate(blks):
                    last=b[-1]
                    if CS_GRP_JUMP in last["groups"]:
                        try:
                            tgt=int(last["op_str"],16)
                            for j,bb in enumerate(blks):
                                if bb[0]["address"]==tgt: edges.append({"from":i,"to":j})
                        except: pass
                st.json({"nodes":nodes,"edges":edges})
        else: st.error("streamlit-aggrid missing")
   
  # 28 Structural Diff
    with tabs[28]:
        if data1 and data2: st.json(structural_diff(blocks1,blocks2))
        else: st.info("Need two files")
   
  # 29 Perceptual Hash
    with tabs[29]:
        _,blks,_=pick_file("phash")
        if blks:
            sel=st.selectbox("Block",range(len(blks)),format_func=lambda x:f"Block {x}")
            st.code(perceptual_block_hash(blks[sel]))
   
  # 30 Version Timeline
    with tabs[30]:
        vers_files=st.file_uploader("Upload multiple versions",accept_multiple_files=True,key="versions")
        if vers_files:
            files=[(f.name,f.read()) for f in vers_files]
            vers,changes=version_timeline(files)
            st.write("Versions:",vers); st.write("Changes:",changes)
   
  # 31 PDF Report
    with tabs[31]:
        if data1:
            pe_info = None
            if PE_AVAIL:
                try:
                    pe_info = pefile.PE(data=data1)
                except:
                    pass
            elf_info = None
            if ELF_AVAIL:
                try:
                    elf_info = ELFFile(io.BytesIO(data1))
                except:
                    pass
            pdf_buf = generate_pdf_report("File1", data1, blocks1, insns1, pe_info, elf_info)
            if pdf_buf:
                st.download_button("Download PDF", pdf_buf, "report.pdf", mime="application/pdf")
            else:
                st.error("reportlab not installed")
        else:
            st.info("No file")
    
  # 32 ML Classify
    with tabs[32]:
        if ML_AVAIL:
            if insns1:
                vec,clf=train_ml_model(); probs=classify_sample(insns1,vec,clf)
                st.bar_chart(probs)
            else: st.info("No instructions")
        else: st.error("scikit-learn missing")
    
  # 33 Plugins
    with tabs[33]:
        st.write("Loaded plugins:")
        for name in st.session_state.plugins: st.write(f"- {name}")
        if not st.session_state.plugins: st.info("Load a plugin in the sidebar")
   
  # 34 Block Patcher
    with tabs[34]:
        _,blks,_=pick_file("patcher")
        if blks:
            sel=st.selectbox("Block to patch",range(len(blks)),format_func=lambda x:f"Block {x}")
            blk=blks[sel]; st.code(block_to_text(blk))
            new_code=st.text_area("New assembly (demo: NOPs only)","ret")
            if st.button("Generate patched file") and data1:
                new_data=bytearray(data1)
                for insn in blk:
                    addr=insn["address"]-base
                    if addr+insn["size"]<=len(new_data): new_data[addr:addr+insn["size"]]=b'\x90'*insn["size"]
                st.download_button("Download patched",bytes(new_data),"patched.bin")
        else: st.info("No file")


if __name__=="__main__":
    main()
