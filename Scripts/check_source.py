#!/usr/bin/env python3
"""Optional Linux/Mac structure checks. NOT Swift compilation or runtime tests.
Requires pip install tree-sitter tree-sitter-swift openstep-parser pyyaml
"""
from pathlib import Path
import plistlib, json, csv, xml.etree.ElementTree as ET
from tree_sitter import Language, Parser
import tree_sitter_swift
from openstep_parser import OpenStepDecoder
import yaml
root=Path(__file__).resolve().parents[1]
parser=Parser(Language(tree_sitter_swift.language()))
errors=[]; files=list(root.rglob('*.swift'))
for file in files:
    tree=parser.parse(file.read_bytes())
    def walk(node):
        if node.type=='ERROR' or node.is_missing: errors.append(f'{file.relative_to(root)}:{node.start_point}')
        for child in node.children: walk(child)
    walk(tree.root_node)
assert not errors, errors
for path in [root/'Info.plist',root/'Resources/PrivacyInfo.xcprivacy']: plistlib.loads(path.read_bytes())
for path in root.glob('Resources/Assets.xcassets/**/Contents.json'): json.loads(path.read_text())
ET.parse(root/'NetScope.xcodeproj/xcshareddata/xcschemes/NetScope.xcscheme')
with (root/'NetScope.xcodeproj/project.pbxproj').open() as f: project=OpenStepDecoder.ParseFromFile(f)
refs=[]
for value in project['objects'].values():
    if value.get('isa')=='PBXFileReference' and value.get('sourceTree')=='<group>':
        path=root/value['path']; assert path.exists(), path; refs.append(path)
assert set(files)==set(p for p in refs if p.suffix=='.swift'), 'Some Swift files are missing from project'
yaml.safe_load((root/'project.yml').read_text())
with (root/'Docs/FEATURE_BACKLOG.csv').open() as f: rows=list(csv.DictReader(f))
assert len(rows)==180 and [int(r['Original ID']) for r in rows]==list(range(1,181))
report={'swift_files_syntax_parsed':len(files),'swift_lines':sum(len(p.read_text().splitlines()) for p in files),'syntax_errors':errors,'project_objects':len(project['objects']),'project_references_exist':True,'plist_xml_json_yaml_valid':True,'backlog_rows':len(rows),'swift_compiled':False,'xctests_executed':False,'device_tested':False,'production_certified':False}
(root/'Docs/STRUCTURAL_CHECKS.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
