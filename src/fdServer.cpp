#include <fdServer.hh>

FdServer::FdServer()
{

    static struct fd_config conf;
    extern struct fd_config *fd_g_config;
    fd_g_config = &conf;
    memset(fd_g_config, 0, sizeof(struct fd_config));
    fd_libproto_init();
    fd_hooks_init();
    fd_conf_init();
    fd_dict_base_protocol(fd_g_config->cnf_dict);
}

void FdServer::startServer(uint16_t port, int family)
{
    struct fd_endpoint *ep;
    ep = (struct fd_endpoint *)malloc(sizeof(struct fd_endpoint));
    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    memset(ep, 0, sizeof(struct fd_endpoint));
    saddr.sin_family = family;
    saddr.sin_addr.s_addr = inet_addr("192.168.222.132");
    saddr.sin_port = htons(port);
    ep->sin = saddr;
    if ((listener = fd_cnx_serv_tcp(port, family, ep)) < 0)
    {
        perror("socket failedd");
        exit(EXIT_FAILURE);
    }

    if (fd_cnx_serv_listen(listener))
    {
        perror("listen failedd");
        exit(EXIT_FAILURE);
    }

    cout << "listen server" << endl;

    if ((server = fd_cnx_serv_accept(listener)) < 0)
    {
        perror("accept failedd");
        exit(EXIT_FAILURE);
    }

    cout << "accept" << endl;

    while (server)
    {
        cout << "while" << endl;
        if (fd_cnx_start_clear(server, 0))
        {
            perror("start clear failedd");
            exit(EXIT_FAILURE);
        }
        cout << "start server" << endl;

        if (fd_cnx_receive(server, NULL, &rcv_buf, &rcv_sz))
        {
            perror("receive failedd");
            exit(EXIT_FAILURE);
        }
        cout << "receive server" << endl;
        // int ret;
        if (checkMsg(&msg, &rcv_buf, rcv_sz))
        {
            perror("msg failedd");
            exit(EXIT_FAILURE);
        }
        cout << "check msg" << endl;

        print(&msg);

        fd_msg_bufferize(msg, &cer_buf, &cer_sz);
        fd_msg_free(msg);

        if (fd_cnx_send(server, cer_buf, cer_sz))
        {
            perror("send failedd");
            exit(EXIT_FAILURE);
        }

        cout << "send server" << endl;
    }
    fd_cnx_destroy(server);
}

struct avp *FdServer::initializeAVP(const void *what, uint8_t *data)
{
    struct dict_object *model = NULL;
    struct avp *oh;
    union avp_value value;
    cout << what << endl;
    /* Now find the $what dictionary object */
    int ret = fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_CODE, what,
                             &model, ENOENT);
    cout << ret << endl;
    /* Create the instance */
    fd_msg_avp_new(model, 0, &oh);
    value.os.data = data;
    value.os.len = strlen((char *)value.os.data);
    fd_msg_avp_setvalue(oh, &value);

    return oh;
}

struct msg *FdServer::initializeCEA()
{
    struct dict_object *model = NULL;
    struct msg *cer;
    struct avp_hdr *pdata;
    fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME,
                   "Capabilities-Exchange-Answer", &model, ENOENT);

    fd_msg_new(model, 0, &cer);

    return cer;
}

void FdServer::print(struct msg **msg)
{
    struct avp_hdr *pdata;
    struct avp *avp = NULL;
    int i = 1;

    fd_msg_browse_internal(*msg, MSG_BRW_FIRST_CHILD, (msg_or_avp **)&avp, NULL);

    struct msg *cer = initializeCEA();
    while (avp)
    {
        fd_msg_avp_hdr(avp, &pdata);

        fd_msg_avp_add(cer, MSG_BRW_LAST_CHILD, initializeAVP((const int *)&pdata->avp_code, (uint8_t *)"1"));
        cout << "avp" << i << ": " << pdata->avp_code << ", "
             << pdata->avp_value->os.data << endl;

        struct avp *nextavp = NULL;
        fd_msg_browse_internal(avp, MSG_BRW_NEXT, (msg_or_avp **)&nextavp, NULL);
        avp = nextavp;
        i++;
    };
    fd_msg_free(*msg);
    *msg = cer;
}

int FdServer::checkMsg(struct msg **cer, unsigned char **buffer,
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
                 fd_cnx_getid(server));
        fd_hook_call(HOOK_PEER_CONNECT_FAILED, NULL, NULL, buf, NULL);

        return 11;
    });

    CHECK_FCT_DO(fd_msg_hdr(msg, &hdr), { return 1; });
    CHECK_PARAMS_DO(
        (hdr->msg_appl == 0) && (hdr->msg_flags & CMD_FLAG_REQUEST) &&
            (hdr->msg_code == CC_CAPABILITIES_EXCHANGE),
        {
            cout << endl
                 << "appl:" << hdr->msg_appl
                 << " flag:" << unsigned(hdr->msg_flags)
                 << " code:" << hdr->msg_code << endl;
            /* Parsing failed -- trace details */
            char buf[1024];
            snprintf(buf, sizeof(buf),
                     "Expected CER from '%s', received a different message, "
                     "connection aborted.",
                     fd_cnx_getid(server));
            fd_hook_call(HOOK_PEER_CONNECT_FAILED, msg, NULL, buf, NULL);
            return 12;
        });
    *cer = msg;
    cout << endl
         << "appl:" << hdr->msg_appl << " flag:" << unsigned(hdr->msg_flags)
         << " code:" << hdr->msg_code << endl;
    return 0;
}
