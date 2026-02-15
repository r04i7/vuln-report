import xml.etree.ElementTree as ET
import sqlite3
from models import get_db_connection, init_db

def parse_and_import_xml(file_path_or_content, is_content=False):
    """
    Parses CVDXML and inserts into SQLite.
    Accepts either a file path or raw XML string.
    """
    try:
        if is_content:
            root = ET.fromstring(file_path_or_content)
        else:
            tree = ET.parse(file_path_or_content)
            root = tree.getroot()

        conn = get_db_connection()
        c = conn.cursor()
        
        count = 0
        # Navigate to <Vulns> -> <Vuln>
        # Adjust path based on your specific XML structure (CombinedData/Vulns/Vuln)
        vulns = root.findall(".//Vuln")
        
        for vuln in vulns:
            # Safe extraction helper
            def get_val(tag):
                node = vuln.find(tag)
                return node.text.strip() if node is not None and node.text else ""

            data = (
                get_val("Id"),
                get_val("Title"),
                get_val("FullDescription"),
                get_val("ThreatCapability"),
                get_val("FullGeneralRemediation"),
                get_val("CWEPrimaryNumber"),
                get_val("CVSSv3VectorString") or get_val("CVSSVectorString"),
                get_val("NIST5PtLikelihood"),
                get_val("NIST5PtImpact")
            )

            # Insert or Update to prevent duplicates
            c.execute('''
                INSERT OR REPLACE INTO vulnerabilities 
                (id, title, description, impact, remediation, cwe, cvss_vector, likelihood, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', data)
            count += 1

        conn.commit()
        conn.close()
        return {"status": "success", "imported_count": count}

    except ET.ParseError as e:
        return {"status": "error", "message": f"XML Parse Error: {str(e)}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    # For testing manually
    init_db()
    result = parse_and_import_xml("../data/CVDXML.xml") # Adjust path as needed
    print(result)