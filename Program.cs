using System;
using System.Net;
using System.Net.Sockets;

namespace RawIcmpPMTUD
{
    class Program
    {
        static void Main(string[] args)
        {
            // Paramètres à adapter selon votre environnement
            // Adresse source (celle de l'interface utilisée) et destination
            string sourceIpStr = "172.20.10.2";   // par exemple, votre adresse locale
            string destinationIpStr = "8.8.4.4";      // exemple : destination (Google DNS ici)
            // Valeur MTU à communiquer (Next-Hop MTU)
            ushort nextHopMtu = 200; // valeur en octets

            IPAddress srcIP = IPAddress.Parse(sourceIpStr);
            IPAddress dstIP = IPAddress.Parse(destinationIpStr);

            try
            {
                // Envoi du paquet ICMP « Packet Too Big » (PMTUD)
                SendIcmpPmtudPacket(srcIP, dstIP, nextHopMtu);
                Console.WriteLine("Paquet ICMP 'Packet Too Big' envoyé de la source PMTUD.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Erreur : " + ex.Message);
            }
        }

        /// <summary>
        /// Construit et envoie un paquet ICMP « Packet Too Big » (Destination Unreachable, Code 4)
        /// avec le champ Next-Hop MTU renseigné.
        /// </summary>
        /// <param name="srcIP">Adresse IP source</param>
        /// <param name="dstIP">Adresse IP destination</param>
        /// <param name="nextHopMtu">Valeur de la MTU à communiquer</param>
        public static void SendIcmpPmtudPacket(IPAddress srcIP, IPAddress dstIP, ushort nextHopMtu)
        {
            // Création d'un socket brut (ProtocolType.IP) pour envoyer un paquet complet (IP + ICMP)
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            // On indique que nous fournissons nous-mêmes l'en‑tête IP
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            socket.Bind(new IPEndPoint(srcIP, 0));

            // Construction du paquet ICMP
            byte[] icmpPacket = BuildIcmpPacket(nextHopMtu);

            // Calcul de la longueur totale du paquet IP : 20 octets (en‑tête IP) + taille de l’ICMP
            int totalLength = 20 + icmpPacket.Length;
            // Identifiant aléatoire pour l’en‑tête IP
            ushort identification = (ushort)new Random().Next(0, ushort.MaxValue);
            // Construction de l’en‑tête IP (sans options)
            byte[] ipHeader = BuildIpHeader(srcIP, dstIP, totalLength, identification);

            // Assemblage complet : IP header suivi du paquet ICMP
            byte[] packet = new byte[ipHeader.Length + icmpPacket.Length];
            Buffer.BlockCopy(ipHeader, 0, packet, 0, ipHeader.Length);
            Buffer.BlockCopy(icmpPacket, 0, packet, ipHeader.Length, icmpPacket.Length);

            // Envoi du paquet (la destination est indiquée via l'IP ; le port n'est pas utilisé pour ICMP)
            IPEndPoint remoteEP = new IPEndPoint(dstIP, 0);
            socket.SendTo(packet, remoteEP);

            socket.Close();
        }

        /// <summary>
        /// Construit le paquet ICMP pour « Packet Too Big » :
        /// - Type = 3 (Destination Unreachable)
        /// - Code = 4 (Fragmentation Needed and DF set)
        /// - 2 octets d'Unused (mis à 0)
        /// - 2 octets pour Next-Hop MTU (valeur à envoyer)
        /// - Payload simulé (28 octets, par exemple : en-tête IP + 64 bits de la trame originale)
        /// </summary>
        /// <param name="nextHopMtu">MTU à communiquer</param>
        /// <returns>Tableau d'octets du paquet ICMP</returns>
        public static byte[] BuildIcmpPacket(ushort nextHopMtu)
        {
            // Pour une conformité basique avec RFC 1191, on inclut 28 octets de payload.
            int payloadLength = 28;
            byte[] payload = new byte[payloadLength];
            // Ici, le payload est simplement initialisé à 0 (mais pourrait contenir l'en‑tête original et 8 octets de données)

            // L'en‑tête ICMP standard pour ce type de message est de 8 octets.
            int icmpLength = 8 + payloadLength;
            byte[] icmpPacket = new byte[icmpLength];

            // 1. Champs de l'en‑tête ICMP
            icmpPacket[0] = 3; // Type 3 : Destination Unreachable
            icmpPacket[1] = 4; // Code 4 : Fragmentation Needed (Packet Too Big)
            // Octets 2-3 : Checksum (initialement à 0)
            icmpPacket[2] = 0;
            icmpPacket[3] = 0;
            // Octets 4-5 : Unused (mis à 0)
            icmpPacket[4] = 0;
            icmpPacket[5] = 0;
            // Octets 6-7 : Next-Hop MTU (en ordre réseau)
            icmpPacket[6] = (byte)(nextHopMtu >> 8);
            icmpPacket[7] = (byte)(nextHopMtu & 0xFF);

            // 2. Copie du payload (ici, 28 octets de 0)
            Buffer.BlockCopy(payload, 0, icmpPacket, 8, payloadLength);

            // 3. Calcul du checksum sur l'ensemble du paquet ICMP
            ushort checksum = ComputeChecksum(icmpPacket);
            icmpPacket[2] = (byte)(checksum >> 8);
            icmpPacket[3] = (byte)(checksum & 0xFF);

            return icmpPacket;
        }

        /// <summary>
        /// Construit l'en‑tête IP (20 octets, sans options) :
        /// - Version 4, IHL = 5
        /// - Longueur totale (en‑tête IP + ICMP)
        /// - Identifiant, Flags (avec DF activé) et Offset
        /// - TTL, Protocole (ICMP = 1)
        /// - Adresses source et destination
        /// - Checksum de l'en‑tête IP
        /// </summary>
        public static byte[] BuildIpHeader(IPAddress srcIP, IPAddress dstIP, int totalLength, ushort identification)
        {
            byte[] ipHeader = new byte[20];

            ipHeader[0] = 0x45; // Version 4 et IHL = 5 (20 octets)
            ipHeader[1] = 0;    // TOS
            ipHeader[2] = (byte)(totalLength >> 8);
            ipHeader[3] = (byte)(totalLength & 0xFF);
            ipHeader[4] = (byte)(identification >> 8);
            ipHeader[5] = (byte)(identification & 0xFF);

            // Flags et Offset de fragment : on active le flag DF (Don't Fragment) => 0x4000
            ushort flagsAndFragment = 0x4000;
            ipHeader[6] = (byte)(flagsAndFragment >> 8);
            ipHeader[7] = (byte)(flagsAndFragment & 0xFF);

            ipHeader[8] = 128;   // TTL
            ipHeader[9] = 1;     // Protocole ICMP (1)
            ipHeader[10] = 0;    // Checksum (initialement 0)
            ipHeader[11] = 0;

            // Adresse IP source
            byte[] srcBytes = srcIP.GetAddressBytes();
            Buffer.BlockCopy(srcBytes, 0, ipHeader, 12, 4);
            // Adresse IP destination
            byte[] dstBytes = dstIP.GetAddressBytes();
            Buffer.BlockCopy(dstBytes, 0, ipHeader, 16, 4);

            // Calcul de la checksum sur l'en‑tête IP
            ushort checksum = ComputeChecksum(ipHeader);
            ipHeader[10] = (byte)(checksum >> 8);
            ipHeader[11] = (byte)(checksum & 0xFF);

            return ipHeader;
        }

        /// <summary>
        /// Calcule la somme de contrôle (checksum) d'un tableau d'octets.
        /// La somme est calculée par addition de mots 16 bits, avec réduction des retenues.
        /// </summary>
        public static ushort ComputeChecksum(byte[] data)
        {
            uint sum = 0;
            int i = 0;
            while (i < data.Length - 1)
            {
                ushort word = (ushort)((data[i] << 8) | data[i + 1]);
                sum += word;
                i += 2;
            }
            if ((data.Length & 1) == 1)
            {
                ushort word = (ushort)(data[data.Length - 1] << 8);
                sum += word;
            }
            // Réduction des retenues
            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            return (ushort)~sum;
        }
    }
}
