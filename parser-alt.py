import hashlib
import re

from defusedxml.ElementTree import parse

from dojo.models import Endpoint, Finding
from django.core.validators import validate_ipv46_address
from django.core.exceptions import ValidationError


class OpenscapParser(object):

    def get_scan_types(self):
        return ["Openscap Vulnerability Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Openscap Vulnerability Scan in XML (OVAL) formats."

    def get_findings(self, file, test):
        tree = parse(file)
        # get root of tree.
        root = tree.getroot()
        namespace = self.get_namespace(root)

        if 'Benchmark' in root.tag and 'http://checklists.nist.gov/xccdf/' in namespace:
            return self.get_xccdf_findings(tree)
        if 'oval_results' in root.tag and 'oval.mitre.org' in namespace:
            return self.get_oval_findingsV2(root)

        # check if xml file hash correct root or not.
        if 'Benchmark' not in root.tag:
            raise ValueError("This doesn't seem to be a valid Openscap vulnerability scan xml file.")
        if 'http://checklists.nist.gov/xccdf/' not in namespace:
            raise ValueError("This doesn't seem to be a valid Openscap vulnerability scan xml file.")

        return []
    
    def get_namespace(self, element):
        """Extract namespace present in XML file."""
        m = re.match(r'\{.*\}', element.tag)
        return m.group(0) if m else ''

    def get_xccdf_findings(self, tree) -> list:
        root = tree.getroot()
        namespace = self.get_namespace(root)
        # read rules
        rules = {}
        for rule in root.findall('.//{0}Rule'.format(namespace)):
            rules[rule.attrib['id']] = {
                "title": rule.findtext('./{0}title'.format(namespace))
            }
        # go to test result
        test_result = tree.find('./{0}TestResult'.format(namespace))
        ips = []
        # append all target in a list.
        for ip in test_result.findall('./{0}target'.format(namespace)):
            ips.append(ip.text)
        for ip in test_result.findall('./{0}target-address'.format(namespace)):
            ips.append(ip.text)

        dupes = dict()
        # run both rule, and rule-result in parallel so that we can get title for failed test from rule.
        for rule_result in test_result.findall('./{0}rule-result'.format(namespace)):
            result = rule_result.findtext('./{0}result'.format(namespace))
            # find only failed report.
            if "fail" in result:
                # get rule corresponding to rule-result
                rule = rules[rule_result.attrib['idref']]
                title = rule['title']
                description = "\n".join([
                    "**IdRef:** `" + rule_result.attrib['idref'] + "`",
                    "**Title:** `" + title + "`",
                ])
                vulnerability_ids = []
                for vulnerability_id in rule_result.findall("./{0}ident[@system='http://cve.mitre.org']".format(namespace)):
                    vulnerability_ids.append(vulnerability_id.text)
                # get severity.
                severity = rule_result.attrib.get('severity', 'medium').lower().capitalize()
                # according to the spec 'unknown' is a possible value
                if severity == 'Unknown':
                    severity = 'Info'
                references = ""
                # get references.
                for check_content in rule_result.findall('./{0}check/{0}check-content-ref'.format(namespace)):
                    references += "**name:** : " + check_content.attrib['name'] + "\n"
                    references += "**href** : " + check_content.attrib['href'] + "\n"

                finding = Finding(
                    title=title,
                    description=description,
                    severity=severity,
                    references=references,
                    dynamic_finding=True,
                    static_finding=False,
                    unique_id_from_tool=rule_result.attrib['idref'],
                )
                if vulnerability_ids:
                    finding.unsaved_vulnerability_ids = vulnerability_ids
                finding.unsaved_endpoints = []
                for ip in ips:
                    try:
                        validate_ipv46_address(ip)
                        endpoint = Endpoint(host=ip)
                    except ValidationError:
                        if '://' in ip:
                            endpoint = Endpoint.from_uri(ip)
                        else:
                            endpoint = Endpoint.from_uri('//' + ip)
                    finding.unsaved_endpoints.append(endpoint)

                dupe_key = hashlib.sha256(references.encode('utf-8')).hexdigest()
                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    if finding.references:
                        find.references = finding.references
                    find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                else:
                    dupes[dupe_key] = finding

        return list(dupes.values())

    def get_oval_findingsV1(self, root) -> list:
        namespace = self.get_namespace(root)
        # find table with vulnerability reports
        dupes = dict()
        for table in root.findall('.//{0}table'.format(namespace)):
            if 'border' in table.attrib.keys() and table.attrib['border'] == '1':
                for tr in table.findall('.//{0}tr'.format(namespace)):
                    if 'class' in  tr.attrib.keys() and  \
                        tr.attrib['class'] == 'Title' and \
                        tr[0].text == 'OVAL Definition Results':
                        dupes = self.parse_vulnerability_table(table)
                        break

        return list(dupes.values())
    
    def parse_vulnerability_table(self, table: dict) -> dict:
        dupes = dict()
        for tr in table:
            if 'class' in tr.attrib.keys() and tr.attrib['class'].startswith("resultbad"):
                finding = self.save_report(tr)
                dupe_key = hashlib.sha256(finding.references.encode('utf-8')).hexdigest()
                if finding != None:
                    dupes[dupe_key] = finding
        
        return dupes
    
    def save_report(self, tr: dict) -> Finding:
        if len(tr) != 5 and tr[1].text != "false" and tr[2].text != "vulnerability":
            return None
        references = ""
        vulnerability_ids = []
        for td in tr[3]:
            references += td.attrib['href'] + "\n"
            vulnerability_ids.append(td.text)
        finding = Finding(
                    title=tr[4].text,
                    description=tr[2].text,
                    severity="Critical",
                    references=references,
                    dynamic_finding=True,
                    static_finding=False,
                    unique_id_from_tool=tr[0].text,
                )
        if vulnerability_ids:
                finding.unsaved_vulnerability_ids = vulnerability_ids
        finding.unsaved_endpoints = []

        return finding

    def get_oval_findingsV2(self, root):
        # find table with vulnerability reports
        dupes = dict()
        for field in root:
            if 'oval_definition' in field.tag:
                if len(field) > 1 and 'definitions' in field[1].tag:
                    for definition in field[1]:
                        if 'id' in definition.attrib.keys() and 'class' in definition.attrib.keys() and definition.attrib['class'] == 'vulnerability':
                            finding = self.save_finding(definition)
                            if finding != None and self.isResult(root, finding.unique_id_from_tool):
                                dupe_key = hashlib.sha256(finding.references.encode('utf-8')).hexdigest()
                                dupes[dupe_key] = finding
                                
        return list(dupes.values())

    def save_finding(self, definition: dict) -> str:

        if len(definition) != 2 and not 'metadata' in definition[0]:
            return None
        unique_id_from_tool = definition.attrib['id']
        metadata = definition[0]
        title = ""
        references = ""
        vulnerability_ids = []
        description = ""
        severity=""
        for field in metadata:
            if 'title' in field.tag:
                title = field.text
                continue
            if 'reference' in field.tag and 'ref_url' in  field.attrib.keys() and 'ref_id' in  field.attrib.keys():
                references += field.attrib['ref_url'] + "\n"
                vulnerability_ids.append(field.attrib['ref_id'])
                continue
            if 'description' in field.tag:
                description = field.text
                continue
            if 'advisory' in field.tag and len(field) > 0:
                severity = field[0].text
            if 'bdu' in field.tag and len(field) > 0:
                if field[0].text == "Средний":
                    severity = "Medium"
                    continue
                if field[0].text == "Критический":
                    severity = "Critical"
                    continue
                if field[0].text == "Высокий":
                    severity = "High"
                    continue
                if field[0].text == "Низкий":
                    severity = "Low"
    
        finding = Finding(
                    title=title,
                    description=description,
                    severity=severity,
                    references=references,
                    dynamic_finding=False,
                    static_finding=True,
                    unique_id_from_tool=unique_id_from_tool,
                )
        if vulnerability_ids:
                finding.unsaved_vulnerability_ids = vulnerability_ids
        finding.unsaved_endpoints = []

        return finding

    def isResult(self, root: dict, unique_id_from_tool: str) -> bool:
            for field in root:
                if len(field) == 1 and 'results' in field.tag and 'system' in field[0].tag:
                    for definition in field[0][0]:
                        if 'definition_id' in definition.attrib.keys() and definition.attrib['definition_id'] == unique_id_from_tool:
                            if definition.attrib['result'] == "false":
                                return False
                            else:
                                return True
            return False

def main() -> int:
    """Echo the input arguments to standard output"""
    phrase = shlex.join(sys.argv)
    echo(phrase)
    return 0

if __name__ == '__main__':
    main()

