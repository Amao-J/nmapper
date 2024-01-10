import subprocess as sp
import xml.etree.ElementTree as ET

class NumPy():
    def __init__(self, command=[]):
        self.command = command

    def scan(self):
        try:
           
            with open("nmap_output.xml", "w") as output_file:
                p = sp.Popen(self.command, shell=False, stdout=output_file, stderr=sp.PIPE)
                out, err = p.communicate()

            print("\n Nmap scan is complete")

            # Read the saved file for further processing
            with open("nmap_output.xml", "r") as file:
                xml_str = file.read()

            root = ET.fromstring(xml_str)
            tag = root.tag
            hosts = []

            for host in root.findall("host"):
                details = {"address": host.find("address").attrib.get('addr'),
                           "name": host.find('hostnames').find('hostname').attrib.get('name')}
                print(str(host))
                port_list = []
                ports = host.find('ports')
                for port in ports:
                    port_details = {"port": port.attrib.get("portid"), "protocol": port.attrib.get("protocol")}

                    service = port.find("service")
                    state = port.find("state")

                    if service is not None:
                        port_details.update({"service": service.attrib.get("service"),
                                             "product": service.attrib.get("product", ""),
                                             "version": service.attrib.get("version", ""),
                                             "extrainfo": service.attrib.get("extrainfo", ""),
                                             "ostype": service.attrib.get("ostype", ""),
                                             "cpe": service.attrib.get("cpe")
                                             })

                        if state is not None:
                            port_details.update({"state": state.attrib.get("state"), "reason": state.attrib.get("reason", "")})

                        port_list.append(port_details)
                details["ports"] = port_list
                hosts.append(details)

            for host in hosts:
                print('_______________________________')
                print(f"Name:{host.get('name', '')}")
                print(f"IP:{host.get('address', '')}")
                print('_______________________________')
                print("services")

                for port in host["ports"]:
                    print("\t Services")

                    for k, v in port.items():
                        print(f"\t \t {k}:{v}")

        except Exception as ex:
            print(f"Exception caught {ex}")

nmap = NumPy(["nmap", "-Pn", "-sV", "-oX", "-", "127.0.0.1"])
nmap.scan()