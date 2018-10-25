// This file is part of BOINC.
// http://boinc.berkeley.edu
// Copyright (C) 2008 University of California
//
// BOINC is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// BOINC is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with BOINC.  If not, see <http://www.gnu.org/licenses/>.

// boinccmd: command-line interface to a BOINC client,
// using GUI RPCs.
//
// usage: boinccmd [--host hostname] [--passwd passwd] command

#if defined(_WIN32) && !defined(__STDWX_H__) && !defined(_BOINC_WIN_) && !defined(_AFX_STDAFX_H_)
#include "boinc_win.h"
#endif

#ifdef _WIN32
#include "win_util.h"
#else
#include "config.h"
#include <cstdio>
#include <cstring>
#include <unistd.h>
#endif

#include <vector>
#include <string>
using std::vector;
using std::string;

#include "gui_rpc_client.h"
#include "error_numbers.h"
#include "util.h"
#include "str_util.h"
#include "str_replace.h"
#include "url.h"
#include "version.h"
#include "common_defs.h"

void version(){
    printf("boinccmd,  built from %s \n", PACKAGE_STRING );
    exit(0);
}

void usage() {
    fprintf(stderr, "\n\
usage: boinccmd [--host hostname] [--passwd passwd] [--unix-domain] command\n\n\
default hostname: localhost\n\
default password: contents of gui_rpc_auth.cfg\n\
Commands:\n\
 --acct-mgr attach URL name passwd  attach to account manager\n\
 --acct-mgr info                    show current account manager info\n\
 --acct-mgr sync                    synchronize with acct mgr\n\
 --acct-mgr detach                  detach from acct mgr\n\
 --client-version                   show client version\n\
 --create-account URL email passwd name\n\
 --file-transfer URL filename op    file transfer operation\n\
   op = retry | abort\n\
 --get-app-config URL               show app config for given project\n\
 --get-cc-status\n\
 --get-daily-xfer-history           show network traffic history\n\
 --get-disk-usage                   show disk usage\n\
 --get-file-transfers               show file transfers\n\
 --get-host-info\n\
 --get-message-count                show largest message seqno\n\
 --get-messages [ seqno ]           show messages > seqno\n\
 --get-notices [ seqno ]            show notices > seqno\n\
 --get-project-config URL\n\
 --get-project-status               show status of all attached projects\n\
 --get-proxy-settings\n\
 --get-simple-gui-info              show status of projects and active tasks\n\
 --get-state                        show entire state\n\
 --get-tasks                        show tasks\n\
 --get-old-tasks                    show reported tasks from last 1 hour\n\
 --join-acct-mgr URL name passwd    same as --acct-mgr attach\n\
 --lookup-account URL email passwd\n\
 --network-available                retry deferred network communication\n\
 --project URL op                   project operation\n\
   op = reset | detach | update | suspend | resume | nomorework | allowmorework | detach-when-done | dont-detach-when-done\n\
 --project-attach URL auth          attach to project\n\
 --quit                             tell client to exit\n\
 --quit-acct-mgr                    same as --acct-mgr detach\n\
 --read-cc-config\n\
 --read-global-prefs-override\n\
 --run-benchmarks\n\
 --set-gpu-mode mode duration       set GPU run mode for given duration\n\
   mode = always | auto | never\n\
 --set-host-info product_name\n\
 --set-network-mode mode duration   set network mode for given duration\n\
   mode = always | auto | never\n\
 --set-proxy-settings\n\
 --set-run-mode mode duration       set run mode for given duration\n\
   mode = always | auto | never\n\
 --task url task_name op            task operation\n\
   op = suspend | resume | abort\n\
"
);
    exit(1);
}

char* next_arg(int argc, char** argv, int& i) {
    if (i >= argc) {
        fprintf(stderr, "Missing command-line argument\n");
        usage();
        exit(1);
    }
    return argv[i++];
}

const char* prio_name(int prio) {
    switch (prio) {
    case MSG_INFO: return "low";
    case MSG_USER_ALERT: return "user notification";
    case MSG_INTERNAL_ERROR: return "internal error";
    }
    return "unknown";
}

void acct_mgr_do_rpc(
    RPC_CLIENT& rpc, char* am_url, char* am_name, char* am_passwd
) {
    int retval;
    if (am_url) {
        retval = rpc.acct_mgr_rpc(am_url, am_name, am_passwd);
    } else {
        retval = rpc.acct_mgr_rpc(0, 0, 0, true);
    }
    if (!retval) {
        while (1) {
            printf("polling for reply\n");
            ACCT_MGR_RPC_REPLY amrr;
            retval = rpc.acct_mgr_rpc_poll(amrr);
            if (retval) {
                printf("poll status: %s\n", boincerror(retval));
            } else {
                if (amrr.error_num) {
                    printf("poll status: %s\n", boincerror(amrr.error_num));
                    if (amrr.error_num != ERR_IN_PROGRESS) break;
                    boinc_sleep(1);
                } else {
                    int j, n = (int)amrr.messages.size();
                    if (n) {
                        printf("Messages from account manager:\n");
                        for (j=0; j<n; j++) {
                            printf("%s\n", amrr.messages[j].c_str());
                        }
                    }
                    break;
                }
            }
        }
    }
}

int main(int argc, char** argv) {
    RPC_CLIENT rpc;
    int i, retval, port=0;
    MESSAGES messages;
    NOTICES notices;
    char passwd_buf[256], hostname_buf[256], *hostname=0;
    char* passwd = passwd_buf, *p, *q;
    bool unix_domain = false;

#ifdef _WIN32
    chdir_to_data_dir();
#endif
    safe_strcpy(passwd_buf, "");
    read_gui_rpc_password(passwd_buf);

#if defined(_WIN32) && defined(USE_WINSOCK)
    WSADATA wsdata;
    retval = WSAStartup( MAKEWORD( 1, 1 ), &wsdata);
    if (retval) {
        fprintf(stderr, "WinsockInitialize: %d\n", retval);
        exit(1);
    }
#endif
    if (argc < 2) usage();
    i = 1;
    if (!strcmp(argv[i], "--help")) usage();
    if (!strcmp(argv[i], "-h"))     usage();
    if (!strcmp(argv[i], "--version")) version();
    if (!strcmp(argv[i], "-V"))     version();

    if (!strcmp(argv[i], "--host")) {
        if (++i == argc) usage();
        strlcpy(hostname_buf, argv[i], sizeof(hostname_buf));

        // see if port is specified.
        // syntax:
        // [a:b:..]:port for IPv6
        // a.b.c.d:port for IPv4
        // hostname:port for domain names
        //
        p = strchr(hostname_buf, '[');
        if (p) {
            q = strchr(p, ']');
            if (!q) {
                fprintf(stderr, "invalid IPv6 syntax: %s\n", hostname_buf);
                exit(1);
            }
            hostname = p+1;
            *q = 0;
            port = atoi(q+1);
        } else {
            hostname = hostname_buf;
            p = strchr(hostname, ':');
            if (p) {
                q = strchr(p+1, ':');
                if (!q) {
                    port = atoi(p+1);
                    *p=0;
                }
            }
        }
        i++;
    }
    if ((i<argc)&& !strcmp(argv[i], "--passwd")) {
        if (++i == argc) usage();
        passwd = argv[i];
        i++;
    }
    if (i == argc) usage();
    if (!(strcmp(argv[i], "--unix_domain") || strcmp(argv[i], "--unix-domain"))) {
        unix_domain = true;
        i++;
    }
    if (i == argc) usage();

    // change the following to debug GUI RPC's asynchronous connection mechanism
    //
#if 1
    if (unix_domain) {
        retval = rpc.init_unix_domain();
        if (retval) {
            fprintf(stderr, "can't connect to Unix domain socket\n");
            exit(1);
        }
    } else {
        retval = rpc.init(hostname, port);
        if (retval) {
            fprintf(stderr, "can't connect to %s\n", hostname?hostname:"local host");
            exit(1);
        }
    }
#else
    retval = rpc.init_asynch(hostname, 60., false);
    while (1) {
        retval = rpc.init_poll();
        if (!retval) break;
        if (retval == ERR_RETRY) {
            printf("sleeping\n");
            sleep(1);
            continue;
        }
        fprintf(stderr, "can't connect: %d\n", retval);
        exit(1);
    }
    printf("connected\n");
#endif

    if (strlen(passwd)) {
        retval = rpc.authorize(passwd);
        if (retval) {
            fprintf(stderr, "Authorization failure: %d\n", retval);
            exit(1);
        }
    }

    char* cmd = next_arg(argc, argv, i);
    // TODO: put something here to convert any '_' in cmd to '-'
    if (!strcmp(cmd, "--client-version")) {
        VERSION_INFO vi;
        retval = rpc.exchange_versions(vi);
        if (!retval) {
            printf("Client version: %d.%d.%d\n", vi.major, vi.minor, vi.release);
        }
    } else if (!strcmp(cmd, "--get-state")) {
        CC_STATE state;
        retval = rpc.get_state(state);
        if (!retval) state.print();
    } else if (!strcmp(cmd, "--get-tasks")) {
        RESULTS results;
        retval = rpc.get_results(results);
        if (!retval) results.print();
    } else if (!strcmp(cmd, "--get-old-tasks")) {
        vector<OLD_RESULT> ors;
        retval = rpc.get_old_results(ors);
        if (!retval) {
            for (unsigned int j=0; j<ors.size(); j++) {
                OLD_RESULT& o = ors[j];
                o.print();
            }
        }
    } else if (!strcmp(cmd, "--get-file-transfers")) {
        FILE_TRANSFERS ft;
        retval = rpc.get_file_transfers(ft);
        if (!retval) ft.print();
    } else if (!strcmp(cmd, "--get-daily-xfer-history")) {
        DAILY_XFER_HISTORY dxh;
        retval = rpc.get_daily_xfer_history(dxh);
        if (!retval) dxh.print();
    } else if (!strcmp(cmd, "--get-project-status")) {
        PROJECTS ps;
        retval = rpc.get_project_status(ps);
        if (!retval) ps.print();
    } else if (!strcmp(cmd, "--get-project-urls")) {
        PROJECTS ps;
        retval = rpc.get_project_status(ps);
        if (!retval) ps.print_urls();
    } else if (!strcmp(cmd, "--get-simple-gui-info")) {
        SIMPLE_GUI_INFO info;
        retval = rpc.get_simple_gui_info(info);
        if (!retval) info.print();
    } else if (!strcmp(cmd, "--get-disk-usage")) {
        DISK_USAGE du;
        retval = rpc.get_disk_usage(du);
        if (!retval) du.print();
    } else if (!strcmp(cmd, "--task")) {
        RESULT result;
        char* project_url = next_arg(argc, argv, i);
        safe_strcpy(result.project_url, project_url);
        char* name = next_arg(argc, argv, i);
        safe_strcpy(result.name, name);
        char* op = next_arg(argc, argv, i);
        if (!strcmp(op, "suspend")) {
            retval = rpc.result_op(result, "suspend");
        } else if (!strcmp(op, "resume")) {
            retval = rpc.result_op(result, "resume");
        } else if (!strcmp(op, "abort")) {
            retval = rpc.result_op(result, "abort");
        } else {
            fprintf(stderr, "Unknown op %s\n", op);
        }
    } else if (!strcmp(cmd, "--project")) {
        PROJECT project;
        safe_strcpy(project.master_url, next_arg(argc, argv, i));
        canonicalize_master_url(project.master_url, sizeof(project.master_url));
        char* op = next_arg(argc, argv, i);
        // TODO: replace '_' in op with '-'
        if (!strcmp(op, "reset")) {
            retval = rpc.project_op(project, "reset");
        } else if (!strcmp(op, "suspend")) {
            retval = rpc.project_op(project, "suspend");
        } else if (!strcmp(op, "resume")) {
            retval = rpc.project_op(project, "resume");
        } else if (!strcmp(op, "detach")) {
            retval = rpc.project_op(project, "detach");
        } else if (!strcmp(op, "update")) {
            retval = rpc.project_op(project, "update");
        } else if (!strcmp(op, "nomorework")) {
            retval = rpc.project_op(project, "nomorework");
        } else if (!strcmp(op, "allowmorework")) {
            retval = rpc.project_op(project, "allowmorework");
        } else if (!strcmp(op, "detach-when-done")) {
            retval = rpc.project_op(project, "detach_when_done");
        } else if (!strcmp(op, "dont-detach-when-done")) {
            retval = rpc.project_op(project, "dont_detach_when_done");
        } else {
            fprintf(stderr, "Unknown op %s\n", op);
        }
    } else if (!strcmp(cmd, "--project-attach")) {
        char url[256];
        safe_strcpy(url, next_arg(argc, argv, i));
        canonicalize_master_url(url, sizeof(url));
        char* auth = next_arg(argc, argv, i);
        retval = rpc.project_attach(url, auth, "");
    } else if (!strcmp(cmd, "--file-transfer")) {
        FILE_TRANSFER ft;

        ft.project_url = next_arg(argc, argv, i);
        ft.name = next_arg(argc, argv, i);
        char* op = next_arg(argc, argv, i);
        if (!strcmp(op, "retry")) {
            retval = rpc.file_transfer_op(ft, "retry");
        } else if (!strcmp(op, "abort")) {
            retval = rpc.file_transfer_op(ft, "abort");
        } else {
            fprintf(stderr, "Unknown op %s\n", op);
        }
    } else if (!strcmp(cmd, "--set-run-mode")) {
        char* op = next_arg(argc, argv, i);
        double duration;
        if (i >= argc || (argv[i][0] == '-')) {
            duration = 0;
        } else {
            duration = atof(next_arg(argc, argv, i));
        }
        if (!strcmp(op, "always")) {
            retval = rpc.set_run_mode(RUN_MODE_ALWAYS, duration);
        } else if (!strcmp(op, "auto")) {
            retval = rpc.set_run_mode(RUN_MODE_AUTO, duration);
        } else if (!strcmp(op, "never")) {
            retval = rpc.set_run_mode(RUN_MODE_NEVER, duration);
        } else {
            fprintf(stderr, "Unknown op %s\n", op);
        }
    } else if (!strcmp(cmd, "--set-gpu-mode")) {
        char* op = next_arg(argc, argv, i);
        double duration;
        if (i >= argc || (argv[i][0] == '-')) {
            duration = 0;
        } else {
            duration = atof(next_arg(argc, argv, i));
        }
        if (!strcmp(op, "always")) {
            retval = rpc.set_gpu_mode(RUN_MODE_ALWAYS, duration);
        } else if (!strcmp(op, "auto")) {
            retval = rpc.set_gpu_mode(RUN_MODE_AUTO, duration);
        } else if (!strcmp(op, "never")) {
            retval = rpc.set_gpu_mode(RUN_MODE_NEVER, duration);
        } else {
            fprintf(stderr, "Unknown op %s\n", op);
        }
    } else if (!strcmp(cmd, "--set-host-info")) {
        HOST_INFO h;
        memset(&h, 0, sizeof(h));
        char* pn = next_arg(argc, argv, i);
        safe_strcpy(h.product_name, pn);
        retval = rpc.set_host_info(h);
    } else if (!strcmp(cmd, "--set-network-mode")) {
        char* op = next_arg(argc, argv, i);
        double duration;
        if (i >= argc || (argv[i][0] == '-')) {
            duration = 0;
        } else {
            duration = atof(next_arg(argc, argv, i));
        }
        if (!strcmp(op, "always")) {
            retval = rpc.set_network_mode(RUN_MODE_ALWAYS, duration);
        } else if (!strcmp(op, "auto")) {
            retval = rpc.set_network_mode(RUN_MODE_AUTO, duration);
        } else if (!strcmp(op, "never")) {
            retval = rpc.set_network_mode(RUN_MODE_NEVER, duration);
        } else {
            fprintf(stderr, "Unknown op %s\n", op);
        }
    } else if (!strcmp(cmd, "--get-proxy-settings")) {
        GR_PROXY_INFO pi;
        retval = rpc.get_proxy_settings(pi);
        if (!retval) pi.print();
    } else if (!strcmp(cmd, "--set-proxy-settings")) {
        GR_PROXY_INFO pi;
        pi.http_server_name = next_arg(argc, argv, i);
        pi.http_server_port = atoi(next_arg(argc, argv, i));
        pi.http_user_name = next_arg(argc, argv, i);
        pi.http_user_passwd = next_arg(argc, argv, i);
        pi.socks_server_name = next_arg(argc, argv, i);
        pi.socks_server_port = atoi(next_arg(argc, argv, i));
        pi.socks5_user_name = next_arg(argc, argv, i);
        pi.socks5_user_passwd = next_arg(argc, argv, i);
        pi.noproxy_hosts = next_arg(argc, argv, i);
        if (pi.http_server_name.size()) pi.use_http_proxy = true;
        if (pi.http_user_name.size()) pi.use_http_authentication = true;
        if (pi.socks_server_name.size()) pi.use_socks_proxy = true;
        retval = rpc.set_proxy_settings(pi);
    } else if (!strcmp(cmd, "--get-message-count")) {
        int seqno;
        retval = rpc.get_message_count(seqno);
        if (!retval) {
            printf("Greatest message sequence number: %d\n", seqno);
        }
    } else if (!strcmp(cmd, "--get-messages")) {
        int seqno;
        if (i == argc) {
            seqno = 0;
        } else {
            seqno = atoi(next_arg(argc, argv, i));
        }
        retval = rpc.get_messages(seqno, messages);
        if (!retval) {
            unsigned int j;
            for (j=0; j<messages.messages.size(); j++) {
                MESSAGE& md = *messages.messages[j];
                strip_whitespace(md.body);
                printf("%d: %s (%s) [%s] %s\n",
                    md.seqno,
                    time_to_string(md.timestamp),
                    prio_name(md.priority),
                    md.project.c_str(),
                    md.body.c_str()
                );
            }
        }
    } else if (!strcmp(cmd, "--get-notices")) {
        int seqno;
        if (i == argc) {
            seqno = 0;
        } else {
            seqno = atoi(next_arg(argc, argv, i));
        }
        retval = rpc.get_notices(seqno, notices);
        if (!retval) {
            unsigned int j;
            for (j=0; j<notices.notices.size(); j++) {
                NOTICE& n = *notices.notices[j];
                strip_whitespace(n.description);
                printf("%d: (%s) %s\n",
                    n.seqno,
                    time_to_string(n.create_time),
                    n.description.c_str()
                );
            }
        }
    } else if (!strcmp(cmd, "--get-host-info")) {
        HOST_INFO hi;
        retval = rpc.get_host_info(hi);
        if (!retval) hi.print();
    } else if (!strcmp(cmd, "--acct-mgr")) {
        char* op = next_arg(argc, argv, i);
        if (!strcmp(op, "attach")) {
            char* am_url = next_arg(argc, argv, i);
            char* am_name = next_arg(argc, argv, i);
            char* am_passwd = next_arg(argc, argv, i);
            acct_mgr_do_rpc(rpc, am_url, am_name, am_passwd);
        } else if (!strcmp(op, "info")) {
            ACCT_MGR_INFO ami;
            retval = rpc.acct_mgr_info(ami);
            if (!retval) ami.print();
        } else if (!strcmp(op, "sync")) {
            acct_mgr_do_rpc(rpc, 0, 0, 0);
        } else if (!strcmp(op, "detach")) {
            retval = rpc.acct_mgr_rpc("", "", "");
        } else {
            printf("unknown operation %s\n", op);
        }
    } else if (!strcmp(cmd, "--join-acct-mgr")) {
        char* am_url = next_arg(argc, argv, i);
        char* am_name = next_arg(argc, argv, i);
        char* am_passwd = next_arg(argc, argv, i);
        acct_mgr_do_rpc(rpc, am_url, am_name, am_passwd);
    } else if (!strcmp(cmd, "--quit-acct-mgr")) {
        retval = rpc.acct_mgr_rpc("", "", "");
    } else if (!strcmp(cmd, "--run-benchmarks")) {
        retval = rpc.run_benchmarks();
    } else if (!strcmp(cmd, "--get-project-config")) {
        char* gpc_url = next_arg(argc, argv,i);
        retval = rpc.get_project_config(string(gpc_url));
        if (!retval) {
            while (1) {
                PROJECT_CONFIG pc;
                retval = rpc.get_project_config_poll(pc);
                if (retval) {
                    printf("poll status: %s\n", boincerror(retval));
                } else {
                    if (pc.error_num) {
                        printf("poll status: %s\n", boincerror(pc.error_num));
                        if (pc.error_num != ERR_IN_PROGRESS) break;
                        boinc_sleep(1);
                    } else {
                        pc.print();
                        break;
                    }
                }
            }
        }
    } else if (!strcmp(cmd, "--lookup-account")) {
        ACCOUNT_IN lai;
        lai.url = next_arg(argc, argv, i);
        lai.email_addr = next_arg(argc, argv, i);
        lai.passwd = next_arg(argc, argv, i);
        retval = rpc.lookup_account(lai);
        printf("status: %s\n", boincerror(retval));
        if (!retval) {
            ACCOUNT_OUT lao;
            while (1) {
                retval = rpc.lookup_account_poll(lao);
                if (retval) {
                    printf("poll status: %s\n", boincerror(retval));
                } else {
                    if (lao.error_num) {
                        printf("poll status: %s\n", boincerror(lao.error_num));
                        if (lao.error_num != ERR_IN_PROGRESS) break;
                        boinc_sleep(1);
                    } else {
                        lao.print();
                        break;
                    }
                }
            }
        }
    } else if (!strcmp(cmd, "--create-account")) {
        ACCOUNT_IN cai;
        cai.url = next_arg(argc, argv, i);
        cai.email_addr = next_arg(argc, argv, i);
        cai.passwd = next_arg(argc, argv, i);
        cai.user_name = next_arg(argc, argv, i);
        retval = rpc.create_account(cai);
        printf("status: %s\n", boincerror(retval));
        if (!retval) {
            ACCOUNT_OUT lao;
            while (1) {
                retval = rpc.create_account_poll(lao);
                if (retval) {
                    printf("poll status: %s\n", boincerror(retval));
                } else {
                    if (lao.error_num) {
                        printf("poll status: %s\n", boincerror(lao.error_num));
                        if (lao.error_num != ERR_IN_PROGRESS) break;
                        boinc_sleep(1);
                    } else {
                        lao.print();
                        break;
                    }
                }
            }
        }
    } else if (!strcmp(cmd, "--read-global-prefs-override")) {
        retval = rpc.read_global_prefs_override();
    } else if (!strcmp(cmd, "--read-cc-config")) {
        retval = rpc.read_cc_config();
        printf("retval %d\n", retval);
    } else if (!strcmp(cmd, "--network-available")) {
        retval = rpc.network_available();
    } else if (!strcmp(cmd, "--set-app-config")) {
        // for testing purposes only
        //
        APP_CONFIGS ac;
        APP_CONFIG a;
        ac.clear();
        strcpy(a.name, "uppercase");
        a.max_concurrent = 2;
        ac.app_configs.push_back(a);
        retval = rpc.set_app_config(next_arg(argc, argv, i), ac);
    } else if (!strcmp(cmd, "--get-app-config")) {
        APP_CONFIGS ac;
        retval = rpc.get_app_config(next_arg(argc, argv, i), ac);
        if (!retval) {
            MIOFILE mf;
            mf.init_file(stdout);
            ac.write(mf);
        }
    } else if (!strcmp(cmd, "--get-cc-status")) {
        CC_STATUS cs;
        retval = rpc.get_cc_status(cs);
        if (!retval) {
            cs.print();
        }
    } else if (!strcmp(cmd, "--quit")) {
        retval = rpc.quit();
    } else {
        usage();
    }
    if (retval) {
        fprintf(stderr, "Operation failed: %s\n", boincerror(retval));
    }

#if defined(_WIN32) && defined(USE_WINSOCK)
    WSACleanup();
#endif
    exit(retval);
}

