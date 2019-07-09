import datetime
from io import BytesIO

from botocore.exceptions import ClientError
from lxml import etree as ET


def store_jar_in_maven_repo(base_dir, group, artifact, version, bucket, file):
	api_dir = "{base}/{group}/{artifact}".format(base=base_dir, group=group.replace(".", "/"), artifact=artifact)

	# Try to get maven-metadata-local from S3; if it exists, update it. If it doesn't exist, create a new one
	maven_metadata_local_filename = api_dir + "/maven-metadata-local.xml"
	try:
		infile = BytesIO()
		bucket.download_fileobj(maven_metadata_local_filename, infile)
		doc = ET.fromstring(infile.getvalue())
		ET.SubElement(doc.findall("./versioning/versions")[0], "version").text = version
		doc.findall("./versioning/release")[0].text = version
		write_xml(bucket, maven_metadata_local_filename, doc)

	except ClientError:
		write_xml(bucket, maven_metadata_local_filename, new_maven_metadata_local(group, artifact, version))

	# Now create an appropriate POM file and jar file in the appropriate di
	api_key_base = "{}/{}/{}-{}".format(api_dir, version, artifact, version)
	write_xml(bucket, api_key_base + ".pom", new_maven_pom(group, artifact, version))
	bucket.put_object(Key=api_key_base + ".jar", Body=file)


def write_xml(bucket, key, xml):
	"""Helper function to write XML to a bucket at a key location. Includes XML declaration.
	Output is formatted so it's easier for a human to read."""
	out = ET.tostring(xml, pretty_print=True, xml_declaration=True, encoding="UTF-8")
	bucket.put_object(Key=key, Body=out)


def new_maven_metadata_local(group, artifact, version):
	"""Generates a new maven-metadata-local XML file, specific to an artifact+group"""
	doc = ET.Element("metadata")
	ET.SubElement(doc, "groupId").text = group
	ET.SubElement(doc, "artifactId").text = artifact
	versioning = ET.SubElement(doc, "versioning")
	ET.SubElement(versioning, "release").text = version
	ET.SubElement(versioning, "lastUpdated").text = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
	versions = ET.SubElement(versioning, "versions")
	ET.SubElement(versions, "version").text = version
	return doc


def new_maven_pom(group, artifact, version):
	"""Generates a new maven POM XML file, specific to an artifact+group"""
	doc = ET.Element("project")
	doc.set("{{{pre}}}schemaLocation".format(pre="http://www.w3.org/2001/XMLSchema-instance"),
			"http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd")
	doc.set("xmlns", "http://maven.apache.org/POM/4.0.0")
	ET.SubElement(doc, "modelVersion").text = "4.0.0"
	ET.SubElement(doc, "groupId").text = group
	ET.SubElement(doc, "artifactId").text = artifact
	ET.SubElement(doc, "version").text = version
	ET.SubElement(doc, "description").text = "POM was created by SoftEng-API-Server maven replacement"
	return doc
