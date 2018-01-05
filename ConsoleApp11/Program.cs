//Mark Frazier 1/4/2018  
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Xml;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System.IO;
using Microsoft.Win32;
using System.Net;
using System.Configuration;

namespace ArtivoVerMan
{
    class Program{
        public static String myIp { get; set; }
        public static String targetIp { get; set; }
        public static String repoTarget { get; set; }
        public static IDictionary<String, String> servers = new Dictionary<String, String>();
        static void Main(string[] args){
            repoTarget = ConfigurationManager.AppSettings["repoTarget"];
            if (repoTarget[repoTarget.Length-1] != '\\'){
                Console.Out.Write("BAD DIRECTORY SET IN CONFIG!! MUST END IN \\");
                throw new Exception();
            }
            String registryPath = @"Software\VB and VBA Program Settings\Ontario Systems API Manager\Profiles";
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;
            if (allDevices.Count == 0){
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }
            // Print the list
            for (int i = 0; i != allDevices.Count; ++i){
                LivePacketDevice device = allDevices[i];
                Console.Write((i + 1) + ". ");
                if (device.Description != null)
                    Console.WriteLine(device.Description);
                else
                    Console.WriteLine(" (No description available)");
            }
            int deviceIndex = 0;
            do{
                Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) || deviceIndex < 1 || deviceIndex > allDevices.Count){
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);
            // Take the selected adapter
            PacketDevice selectedDevice = allDevices[deviceIndex - 1];
            // Open the device
            myIp = selectedDevice.Addresses[1].Address.ToString().Replace("Internet ", "");
            Console.Out.WriteLine("Known servers and addresses:");
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(registryPath)){
                if (key != null){
                    String ipAddr = "";
                    foreach (string subkey in key.GetValueNames()){
                        String val = (string)(key.GetValue(subkey));
                        Match match = Regex.Match(val.Split('\x7')[1], @"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b");
                        if (!match.Success){
                            IPHostEntry hostEntry = null;
                            try{
                                hostEntry = Dns.GetHostEntry(val.Split('\x7')[1]);
                                ipAddr = hostEntry.AddressList[0].ToString();
                            }
                            catch{
                                Console.Out.WriteLine(val.Split('\x7')[1] + " could not be resolved");
                            }
                        }
                        else{
                            ipAddr = val.Split('\x7')[1];
                        }
                        if (!String.IsNullOrEmpty(ipAddr)){
                            Console.Out.Write(val.Split('\x7')[5] + "-" + ipAddr);
                            try{
                                servers.Add(ipAddr, val.Split('\x7')[5]);
                                Console.Out.WriteLine();
                            }
                            catch{
                                Console.Out.WriteLine(" - Duplicate Ip.");
                            }
                        }
                    }
                }
            }
            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.None, 1000)){
                // Check the link layer. We support only Ethernet for simplicity.
                if (communicator.DataLink.Kind != DataLinkKind.Ethernet){
                    Console.WriteLine("This program works only on Ethernet networks.");
                    return;
                }
                // Compile the filter
                Console.WriteLine("Listening on " + selectedDevice.Description + "...");
                Console.WriteLine("--------------------------------------------------");
                // start the capture
                communicator.ReceivePackets(0, PacketHandler);
            }
        }
        // Callback function invoked by libpcap for every incoming packet
        private static void PacketHandler(Packet packet){
            String scriptName = "";
            IpV4Datagram ip = packet.Ethernet.IpV4;
            UdpDatagram udp = ip.Udp;
            String directory = "";
            // print ip addresses and udp ports
            if (ip.Source.ToString() == myIp && servers.ContainsKey(ip.Destination.ToString()) && packet.Length > 100){
                directory = repoTarget + servers[ip.Destination.ToString()] + @"\";
                String pay = "";
                foreach (char paychar in ip.Payload){
                    if ((paychar > 31 && paychar < 177) || paychar == 10 || paychar == 13 || paychar == 9) {
                        pay = pay + paychar;
                    }

                }
                if (pay != ""){
                    Regex rgx = new Regex("(?=\\<\\?xml).*<\\/.*>", RegexOptions.Singleline);
                    if (rgx.Match(pay).Success){
                        pay = rgx.Matches(pay)[0].Value;
                        try{
                            XmlDocument xmlDoc = new XmlDocument();
                            xmlDoc.LoadXml(pay);
                            directory = directory + xmlDoc.LastChild.Name;
                            scriptName = xmlDoc.LastChild.Attributes[0].InnerText;
                                foreach (XmlNode child in xmlDoc.LastChild){
                                    switch (child.Name){
                                        case "CODE":
                                            pay = child.InnerText;
                                            break;
                                    }
                                }
                            directory = directory + "\\" + scriptName + "\\";
                            if (!Directory.Exists(directory)){
                                Directory.CreateDirectory(directory);
                            }
                            Console.WriteLine(directory + "ver" + Directory.GetFiles(@directory, "*.*", SearchOption.AllDirectories).Length);
                            using (StreamWriter writter = new StreamWriter(directory + "ver" + Directory.GetFiles(directory, "*.*", SearchOption.AllDirectories).Length + ".txt")){
                                    writter.Write(pay);
                            }
                        }
                        catch{
                            Console.Out.WriteLine("A bad thing happend when tring to parse XML. Your client may not have deployed the whole thing. Please save again.");
                        }
                    }
                }
            }
        }
    }
}
