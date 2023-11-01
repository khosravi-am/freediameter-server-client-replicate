#include <fdClient.hh>

FdClient::FdClient(uint16_t port, int family)
{

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = family;
    saddr.sin_addr.s_addr = inet_addr("192.168.222.124");
    saddr.sin_port = htons(port);
    socka = (sSA *)&saddr;

    static struct fd_config conf;
    extern struct fd_config *fd_g_config;
    fd_g_config = &conf;
    memset(fd_g_config, 0, sizeof(struct fd_config));
    fd_libproto_init();
    fd_hooks_init();
    fd_conf_init();
    fd_dict_base_protocol(fd_g_config->cnf_dict);
}

struct avp *FdClient::initializeAVP(const void *what, uint8_t *data)
{
    struct dict_object *model = NULL;
    struct avp *oh;
    union avp_value value;
    cout << what << endl;
    /* Now find the $what dictionary object */
    int ret = fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, what,
                             &model, ENOENT);
    cout << ret << endl;
    /* Create the instance */
    fd_msg_avp_new(model, 0, &oh);
    value.os.data = data;
    value.os.len = strlen((char *)value.os.data);
    fd_msg_avp_setvalue(oh, &value);

    return oh;
}

struct msg *FdClient::initializeCER()
{
    struct dict_object *model = NULL;
    struct msg *cer;
    struct avp_hdr *pdata;
    fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME,
                   "Capabilities-Exchange-Request", &model, ENOENT);

    fd_msg_new(model, 0, &cer);

    return cer;
}

void FdClient::startClient()
{
    if ((client = fd_cnx_cli_connect_tcp(socka, sSAlen(socka))) < 0)
    {
        perror("tcp connent failed");
        exit(EXIT_FAILURE);
    }
    cout << "connect client" << endl;

    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline("/home/uiser/p1/freediameterserverclient/fuzz3.pcap", errbuff);
    struct pcap_pkthdr *pkthdr;
    const u_char *packet;

    while (int returnValue = pcap_next_ex(pcap, &pkthdr, &packet) >= 0)
    {
        cout << "while" << endl;
        const struct ether_header *ethernetHeader;
        const struct ip *ipHeader;
        const struct tcphdr *tcpHeader;
        char sourceIp[INET_ADDRSTRLEN];
        char destIp[INET_ADDRSTRLEN];
        u_int sourcePort, destPort;
        u_char *data;
        int dataLength = 0;
        string dataStr = "";

        ethernetHeader = (struct ether_header *)packet;
        if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP)
        {
            ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
            inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

            if (ipHeader->ip_p == IPPROTO_TCP)
            {
                tcpHeader = (tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                sourcePort = ntohs(tcpHeader->source);
                destPort = ntohs(tcpHeader->dest);
                data = (u_char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
                dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            }
        }

        msg = initializeCER();
        fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD,
                       initializeAVP("Origin-Host", (uint8_t *)destIp));
        fd_msg_bufferize(msg, &cer_buf, &cer_sz);
        fd_msg_free(msg);

        if (fd_cnx_start_clear(client, 0))
        {
            perror("start clear failed");
            exit(EXIT_FAILURE);
        }
        cout << "start client" << endl;

        if (fd_cnx_send(client, cer_buf, cer_sz))
        {
            perror("send failedd");
            exit(EXIT_FAILURE);
        }
        cout << "client sent" << endl;
        int ret;
        if ((fd_cnx_receive(client, NULL, &rcv_buf, &rcv_sz)))
        {

            perror("receive failedd");
            exit(EXIT_FAILURE);
        }
        cout << "client receive" << endl;

        if (ret = checkMsg(&msg, &rcv_buf, rcv_sz))
        {
            cout << ret << endl;
            perror("msg failedd");
            exit(EXIT_FAILURE);
        }

        print(msg);

        cout << "check msg" << endl;
    }

    fd_cnx_destroy(client);
}

void FdClient::print(struct msg *msg)
{
    struct avp_hdr *pdata;

    struct avp *avp = NULL;
    int i = 1;
    fd_msg_browse_internal(msg, MSG_BRW_FIRST_CHILD, (msg_or_avp **)&avp, NULL);

    while (avp)
    {
        fd_msg_avp_hdr(avp, &pdata);
        cout << "avp" << i << ": " << pdata->avp_code << ", "
             << pdata->avp_value->os.data << endl;
        struct avp *nextavp = NULL;
        fd_msg_browse_internal(avp, MSG_BRW_NEXT, (msg_or_avp **)&nextavp, NULL);
        avp = nextavp;
        i++;
    };
    fd_msg_free(msg);
}

int FdClient::checkMsg(struct msg **cer, unsigned char **buffer,
                       size_t buflen)
{
    struct msg *msg = NULL;
    struct fd_pei pei;
    struct msg_hdr *hdr = NULL;

    /* Try parsing this message */
    CHECK_FCT_DO(fd_msg_parse_buffer(buffer, buflen, &msg), {
        /* Parsing failed */
        // fd_hook_call(HOOK_MESSAGE_PARSING_ERROR, NULL, NULL, &rcv_data, pmdl
        // );
        return 6;
    });

    CHECK_FCT_DO(fd_msg_parse_rules(msg, fd_g_config->cnf_dict, &pei), {
        /* Parsing failed -- trace details */
        char buf[1024];

        fd_hook_call(HOOK_MESSAGE_PARSING_ERROR, msg, NULL,
                     pei.pei_message ?: pei.pei_errcode, fd_msg_pmdl_get(msg));

        snprintf(buf, sizeof(buf),
                 "Error parsing CER from '%s', connection aborted.",
                 fd_cnx_getid(client));
        fd_hook_call(HOOK_PEER_CONNECT_FAILED, NULL, NULL, buf, NULL);

        return 11;
    });

    CHECK_FCT_DO(fd_msg_hdr(msg, &hdr), { return 1; });
    CHECK_PARAMS_DO((hdr->msg_appl == 0) && (hdr->msg_flags == 0) &&
                        (hdr->msg_code == CC_CAPABILITIES_EXCHANGE),
                    {
                        cout << endl
                             << "appl: " << hdr->msg_appl
                             << " flag: " << unsigned(hdr->msg_flags)
                             << " code: " << hdr->msg_code << endl;
                        /* Parsing failed -- trace details */
                        char buf[1024];
                        snprintf(buf, sizeof(buf),
                                 "Expected CER from '%s', received a different "
                                 "message, connection aborted.",
                                 fd_cnx_getid(client));
                        fd_hook_call(HOOK_PEER_CONNECT_FAILED, msg, NULL, buf,
                                     NULL);
                        return 12;
                    });
    cout << endl
         << "appl: " << hdr->msg_appl << " flag:" << unsigned(hdr->msg_flags)
         << "code: " << hdr->msg_code << endl;
    *cer = msg;
    return 0;
}
