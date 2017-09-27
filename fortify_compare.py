"""
Compares two different fortify files
"""
import sys
from zipfile import ZipFile
import xml.etree.ElementTree as ET
import pandas

class Fulnerability(object):
    """
    A POCO with a different name that vulnerablity since 
    we have so many vulnerability types in this project
    """
    class_info_id = None
    class_info_kingdom = None
    class_info_type = None
    #class_info_subtype = None
    instance_info_id = None
    instance_severity = None
    instance_confidence = None
    source_location = None

class FortifyCompare(object):
    """
    Compare Fortify findings between two different application releases.
    """
    def __init__(self, previous_fpr, current_fpr):
        """
        The init function
        :param previous_fpr: path and name to the previous fpr file.
        :param current_fpr: path and name to the current fpr file.
        """
        self.previous_fpr = previous_fpr
        self.current_fpr = current_fpr


    def obj_arr_to_dataframe(self, arry_of_objects):
        """
        converts array of objects to a dataframe
        :param array_of_objects: array of python objects
        """
        variables = vars(arry_of_objects[0]).keys()
        dframe = pandas.DataFrame([[getattr(i, j)
                                    for j in variables]
                                   for i in arry_of_objects], columns=variables)
        return dframe

    def compare_audits(self, previous, current):
        """
        :param previous: dataframe of the previous fortify scan
        :param current: dataframe of the current fortify scan
        """
        pdf = self.obj_arr_to_dataframe(previous)
        cdf = self.obj_arr_to_dataframe(current)
        dfs_dictionary = {'went_away':pdf, "new_findings":cdf}
        combined = pandas.concat(dfs_dictionary)
        result = combined.drop_duplicates("instance_info_id", keep=False)
        return result

    def get_vulnerabilities(self, raw_xml):
        """
        Parse the XML and return the POCO
        :param raw_xml: string of raw xml
        """
        result = []
        name_space = {'xmlns': 'xmlns://www.fortifysoftware.com/schema/fvdl'}
        doc = ET.fromstring(raw_xml)
        vulnerabilities = doc.findall(".//xmlns:Vulnerability", name_space)
        for vul_xml in vulnerabilities:
            vul = Fulnerability()
            vul.class_info_id = vul_xml.find(".//xmlns:ClassID", name_space).text
            vul.class_info_kingdom = vul_xml.find(".//xmlns:Kingdom", name_space).text
            vul.class_info_type = vul_xml.find(".//xmlns:Type", name_space).text
            #vul.class_info_subtype = vul_xml.find(".//xmlns:Subtype", name_space).text
            vul.instance_info_id = vul_xml.find(".//xmlns:InstanceID", name_space).text
            vul.instance_severity = vul_xml.find(".//xmlns:InstanceSeverity", name_space).text
            vul.instance_confidence = vul_xml.find(".//xmlns:Confidence", name_space).text
            vul.source_location = vul_xml.find(".//xmlns:SourceLocation", name_space).attrib["path"]
            result.append(vul)

        return result

    def execute(self):
        """
        Executes the main sequence.
        """
        zip_previous = ZipFile(self.previous_fpr, 'r')

        # Write old FPR audit xml and fvdl to file system.
        zip_previous.extract('audit.xml', 'FPR_1_' + self.previous_fpr[:-len('.fpr')])
        zip_previous.extract('audit.fvdl', 'FPR_1_' + self.previous_fpr[:-len('.fpr')])

        # Write old FPR audit xml and fvdl to memory.
        previous_audit_xml_content = zip_previous.read('audit.xml')
        previous_fvdl_xml_content = zip_previous.read('audit.fvdl')

        print("Old 'audit.xml'  length: " + str(len(previous_audit_xml_content)))
        print("Old 'audit.fvdl' length: " + str(len(previous_fvdl_xml_content)))

        zip_current = ZipFile(self.current_fpr, 'r')

        # Write new FPR audit xml and fvdl to file system.
        zip_current.extract('audit.xml', 'FPR_2_' + self.current_fpr[:-len('.fpr')])
        zip_current.extract('audit.fvdl', 'FPR_2_' + self.current_fpr[:-len('.fpr')])

        # Write new FPR audit xml and fvdl to memory.
        current_audit_xml_content = zip_current.read('audit.xml')
        current_fvdl_content = zip_current.read('audit.fvdl')

        print("New 'audit.xml'  length: " + str(len(current_audit_xml_content)))
        print("New 'audit.fvdl' length: " + str(len(current_fvdl_content)))

        previous = self.get_vulnerabilities(previous_fvdl_xml_content)
        current = self.get_vulnerabilities(current_fvdl_content)

        results = self.compare_audits(previous, current)
        #print(results)
        output_filename = self.previous_fpr + "_" + self.current_fpr + ".csv"
        results.to_csv(output_filename)
        print("Done!")
        print("Results can be found in the file: " +  output_filename)

if __name__ == "__main__":
    print('Number of arguments:', len(sys.argv), 'arguments.')
    print('Argument List:', str(sys.argv))

    if len(sys.argv) < 2:
        print("Usage: fortify_compare.py [Previous FPR File Name] [Current FPR File Name]")

    # just some default file names
    PREVIOUS_FPR = 'MyPreviousScan.fpr'
    CURRENT_FPR = 'MyCurrentScan.fpr'

    if len(sys.argv) > 1:
        PREVIOUS_FPR = sys.argv[1]

    if len(sys.argv) > 2:
        CURRENT_FPR = sys.argv[2]

    COMPARER = FortifyCompare(PREVIOUS_FPR, CURRENT_FPR)
    COMPARER.execute()
