import sys
from fpdf import FPDF
import re
import os

def count_intercepted_keywords(directory):
    keywords = {}
    with open("TLS-intercept/wordlist.txt", 'r') as file:
        for line in file:
            stripped_line = line.strip()
            if stripped_line:
                keywords[stripped_line] = 0
    messages = 0
    for filename in os.listdir(directory):
        if filename.endswith('.txt'):
            messages += 1
            file_path = os.path.join(directory, filename)
            with open(file_path, 'r') as file:
                first_line = file.readline().strip()
                words = first_line.split(',')
                for word in words:
                    word = word.strip().strip('[]\'') 
                    if word in keywords:
                        keywords[word] += 1
    return keywords, messages

def count_lines(file_path):
    with open(file_path, 'r') as file:
        line_count = sum(1 for line in file)
    return line_count

def parse_database_summary(file_path):
    databases_used = []

    with open(file_path, 'r') as file:
        lines = file.readlines()

    for line in lines:
        key_value = line.strip().split(':')
        if key_value[1] == ' True':
            database_name = key_value[0].split(' ')[0]
            databases_used.append(database_name)

    return databases_used

def find_insecure_protocols(log_file_path):
    insecure_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

    found_insecure_protocols = set()
    protocol_pattern = re.compile(r"Supported Protocols: ([\w\d.,]+)")

    with open(log_file_path, 'r') as file:
        log_contents = file.readlines()

    for line in log_contents:
        match = protocol_pattern.search(line)
        if match:
            protocols = match.group(1).split(',')
            for protocol in protocols:
                if protocol in insecure_protocols:
                    found_insecure_protocols.add(protocol)

    return list(found_insecure_protocols)

def parse_permissions(file_path):
    permission_counts = {
        "Highly Sensitive": 0,
        "Moderately Sensitive": 0,
        "Potentially Sensitive": 0
    }

    categories = list(permission_counts.keys())

    with open(file_path, 'r') as file:
        lines = file.readlines()

    current_category = None
    for line in lines:
        line_category = next((category for category in categories if category in line), None)
        if line_category:
            current_category = line_category
            continue 

        if current_category and "android.permission." in line:
            permission_counts[current_category] += 1

    return permission_counts

def create_pdf(package_name, outdir):
    pdf = FPDF()
    pdf.add_page()

    # Title
    pdf.set_font("Arial", 'B', size=15)
    title = f"Privacy Report for {package_name}"
    pdf.cell(0, 10, txt=title, ln=True, align='C') 
    pdf.cell(0, 10, "", ln=True)


    # MANIFEST ANALYSIS
    pdf.set_font("Arial", 'B', size=12)
    pdf.cell(0, 10, txt="Manifest Analysis", ln=True, align='L')

    exp_activities = count_lines(f"{outdir}/exported-activities.txt")
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, txt=f"Found {exp_activities} exported activities. This can pose a security risk if the activity contains sensitive information or functionality that the application only should access. See exported-activities.txt for full list.")

    # PERMISSIONS
    pdf.set_font("Arial", 'B', size=12)
    pdf.cell(0, 10, txt="Permissions Analysis", ln=True, align='L')

    permission_counts = parse_permissions(f"{outdir}/permissions-summary.txt")

    pdf.set_font("Arial", size=12)
    summary_text = f"The app was granted {permission_counts['Highly Sensitive']} highly sensitive, " \
                   f"{permission_counts['Moderately Sensitive']} moderately sensitive, and " \
                   f"{permission_counts['Potentially Sensitive']} potentially sensitive permissions. " \
                   f"See permissions-summary.txt for more details."
    pdf.multi_cell(0, 10, txt=summary_text)

    # API ANALYSIS
    pdf.set_font("Arial", 'B', size=12)
    pdf.cell(0, 10, txt="API Analysis", ln=True, align='L')

    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, txt="See apis.txt for a list of apis used by the app.", ln=True, align='L')

    # NETWORKING ANALYSIS
    pdf.set_font("Arial", 'B', size=12)
    pdf.cell(0, 10, txt="Networking Analysis", ln=True, align='L')

    keywords, messages = count_intercepted_keywords(f"{outdir}/TLSintercept")
    protocols = find_insecure_protocols(f"{outdir}/encryption_protocol.log")
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, txt=f"Intercepted {messages} messages containing flagged keywords, including:\n {keywords}")
    pdf.multi_cell(0, 10, txt=f"App supports insecure protocols: {str(protocols)}. See encryption_protocol.log for more info.")

    # MEMORY ANALYSIS
    pdf.set_font("Arial", 'B', size=12)
    pdf.cell(0, 10, txt="Memory Analysis", ln=True, align='L')

    mem_ranges = count_lines(f"{outdir}/memory_ranges.log")
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, txt=f"App uses {mem_ranges} memory locations with potentially insecure rwx privileges. Check memory_ranges.log to analyse each location.")

    # DATABASE ANALYSIS
    pdf.set_font("Arial", 'B', size=12)
    pdf.cell(0, 10, txt="Database Analysis", ln=True, align='L')

    dbs = parse_database_summary(f"{outdir}/database_summary.txt")
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, txt=f"Detected the use of: {dbs}", ln=True, align='L')
    pdf.cell(0, 10, txt="To manually check interactions for the storage of private data see db.log.", ln=True, align='L')


    # Save
    out_path = f"{outdir}/privacy-summary.pdf"
    pdf.output(out_path)

    print(f"Privacy summary has been created at {out_path}")


if len(sys.argv) != 3:
    print("Usage: python produce-pdf.py <packagename> <outdir>")
    sys.exit(1)

package_name = sys.argv[1]
outdir = sys.argv[2]

create_pdf(package_name, outdir)
