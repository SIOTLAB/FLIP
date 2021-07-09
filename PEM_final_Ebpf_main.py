#!/usr/bin/python
#
# iwlstrength.py    iwl wifi stregth as audio
#           For Linux, uses BCC, eBPF. Embedded C.
#
# Tone generation from: https://gist.github.com/nekozing/5774628
#
# 29-Apr-2019   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import time
# import numpy


# BPF
b = BPF(text="""


#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>
#include <net/mac80211.h>
#include "/home/siotlab1/Desktop/linux-5.8/net/mac80211/ieee80211_i.h"
#include <uapi/linux/ptrace.h>
#include <linux/dma-mapping.h>
#include "/home/siotlab1/Desktop/linux-5.8/drivers/net/wireless/ath/ath9k/ath9k.h"
#include </home/siotlab1/Desktop/linux-5.8/include/linux/ieee80211.h>
#include </home/siotlab1/Desktop/linux-5.8/include/uapi/linux/time.h>

struct prio_sched_data {
    int bands;
    struct tcf_proto __rcu *filter_list;
    struct tcf_block *block;
    u8  prio2band[TC_PRIO_MAX+1];
    struct Qdisc *queues[TCQ_PRIO_BANDS];
};

int kprobe____ieee80211_beacon_add_tim(struct pt_regs *ctx,struct ieee80211_sub_if_data *sdata,
 struct ps_data *ps, struct sk_buff *skb,
 bool is_template) {

    u64 ts = bpf_ktime_get_ns();

    u64 tim;
    bpf_probe_read(&tim, sizeof(tim), &ps->tim);
    bpf_trace_printk("[2021][ath10k_wmi_event_host_swba] [1] bitmap: %x\\n",  tim);
    

    return 0;
}



int kprobe__ath_tx_process_buffer(struct pt_regs *ctx, struct ath_softc *sc, struct ath_txq *txq,
  struct ath_tx_status *ts, struct ath_buf *bf,
  struct list_head *bf_head)
{
    struct ieee80211_hdr * hdr = (struct ieee80211_hdr *)bf->bf_mpdu->data;
    
    u8 addr1[6],addr2[6];
    bpf_probe_read(&addr1, sizeof(addr1), &hdr->addr1);
    bpf_probe_read(&addr2, sizeof(addr2), &hdr->addr2);


    struct ieee80211_hw *hw = (struct ieee80211_hw *)sc->hw;    




    
    u8 match_addr1[6];

    match_addr1[0] = 0xa4;
    match_addr1[1] = 0x08;
    match_addr1[2] = 0xea;


    if( (match_addr1[0] ==  addr1[0] && match_addr1[1] ==  addr1[1] && match_addr1[1] ==  addr1[1]))
    {
        bpf_trace_printk("[2021][ath_tx_process_bufffer][mac80211_qnum] ... %d\\n", txq->mac80211_qnum);
        bpf_trace_printk("[2021][ath_tx_process_bufffer][axq_qnum] ... %d\\n", txq->axq_qnum);

        bpf_trace_printk("[2021][ath_tx_process_bufffer][axq_depth] ... %d\\n", txq->axq_depth);
        bpf_trace_printk("[2021][ath_tx_process_bufffer][axq_ampdu_depth] ... %d\\n", txq->axq_ampdu_depth);
        bpf_trace_printk("[2021][ath_tx_process_bufffer][txq_tailidx] ... %d\\n", txq->txq_tailidx);
        bpf_trace_printk("[2021][ath_tx_process_bufffer][pending_frames] ... %d\\n", txq->pending_frames);

        bpf_trace_printk("[2021][ath_tx_process_buffer]::7::peerd[1] %x:%x:%x\\n", addr1[0], addr1[1], addr1[2]);
        bpf_trace_printk("[2021][ath_tx_process_buffer]::7::peerd[2] %x:%x:%x\\n", addr1[3], addr1[4], addr1[5]);
    }

    return 0;
}





int kprobe__br_handle_frame_finish(struct pt_regs *ctx,struct net *net, struct sock *sk, struct sk_buff *skb)
{
    
    struct iphdr *ip_header = (struct iphdr *) (skb->head + skb->network_header);
    struct ethhdr *mh = (struct ethhdr *) ( skb->head + skb->mac_header);
    if (skb->mac_len ==14)
    {
        if (ip_header->daddr == 0xf1e0100a)
        {
            bpf_trace_printk("\\n");
            bpf_trace_printk("[2021][br_handle_frame_finish]Source IP[1]=%x\\n",ip_header->daddr);
            bpf_trace_printk("[2021][br_handle_frame_finish]Source MAC[1]=%x:%x:%x\\n",mh->h_dest[0],mh->h_dest[1],mh->h_dest[2]);
        }
    }
    return 0;
}



int kprobe__dev_hard_start_xmit(struct pt_regs *ctx,struct sk_buff *first, struct net_device *dev,
    struct netdev_queue *txq, int *ret)
{
    struct iphdr *ip_header = (struct iphdr *) (first->head + first->network_header);
    struct ethhdr *mh = (struct ethhdr *) ( first->head + first->mac_header);
    if (first->mac_len ==14)
    {
        if (ip_header->daddr == 0xf1e0100a)
        {
            bpf_trace_printk("[2021][dev_hard_start_xmit]Source IP[1]=%x\\n",ip_header->daddr);
            bpf_trace_printk("[2021][dev_hard_start_xmit]Source MAC[1]=%x:%x:%x\\n",mh->h_dest[0],mh->h_dest[1],mh->h_dest[2]);
        }
    }
    return 0;
}

int kprobe__ieee80211_tx_pending(struct pt_regs *ctx)
{
    bpf_trace_printk("[2021][ieee80211_tx_pending]\\n");
    return 0;
}


int kprobe__ieee80211_queue_skb(struct pt_regs *ctx,struct ieee80211_local *local,
    struct ieee80211_sub_if_data *sdata,
    struct sta_info *sta,
    struct sk_buff *skb)
{

    return 0;
}



int kprobe__ieee80211_xmit(struct pt_regs *ctx, struct ieee80211_sub_if_data *sdata,
    struct sta_info *sta, struct sk_buff *skb)
{
    struct ieee80211_hdr * hdr = (struct ieee80211_hdr *)skb->data;

    u8 addr1[6],addr2[6];
    bpf_probe_read(&addr1, sizeof(addr1), &hdr->addr1);
    bpf_probe_read(&addr2, sizeof(addr2), &hdr->addr2);
    u8 match_addr1[6];
    match_addr1[0] = 0xa4;
    match_addr1[1] = 0x8;
    match_addr1[2] = 0xea;

    if( (match_addr1[0] ==  addr1[0] && match_addr1[1] ==  addr1[1] && match_addr1[1] ==  addr1[1]))
    {
        bpf_trace_printk("[2021][ieee80211_xmit]::7::peerd[1] %x:%x:%x\\n", addr1[0], addr1[1], addr1[2]);
        bpf_trace_printk("[2021][ieee80211_xmit]::7::peerd[2] %x:%x:%x\\n", addr1[3], addr1[4], addr1[5]);
    }
    return 0;
}





int kprobe__ath_tx_txqaddbuf(struct pt_regs *ctx,struct ath_softc *sc, struct ath_txq *txq,
   struct list_head *head, bool internal)
{
    
    struct ath_buf *bf = (struct ath_buf *) head->prev;
    struct ieee80211_hdr * hdr = (struct ieee80211_hdr *)bf->bf_mpdu->data;
    u8 addr1[6],addr2[6];
    bpf_probe_read(&addr1, sizeof(addr1), &hdr->addr1);
    bpf_probe_read(&addr2, sizeof(addr2), &hdr->addr2);
    u8 match_addr1[6];
    match_addr1[0] = 0xa4;
    match_addr1[1] = 0x08;
    match_addr1[2] = 0xea;

    if( (match_addr1[0] ==  addr1[0] && match_addr1[1] ==  addr1[1] && match_addr1[1] ==  addr1[1]))
    {
        bpf_trace_printk("[2021][ath_tx_txqaddbuf]::7::peerd[1] %x:%x:%x\\n", addr1[0], addr1[1], addr1[2]);
        bpf_trace_printk("[2021][ath_tx_txqaddbuf]::7::peerd[2] %x:%x:%x\\n", addr1[3], addr1[4], addr1[5]);
    }
    return 0;
}



int kprobe____sta_info_recalc_tim(struct pt_regs *ctx, struct sta_info *sta)
{
    u8 addr1[6];
    bpf_probe_read(&addr1, sizeof(addr1), &sta->sta.addr);

    u8 match_addr1[6];

    match_addr1[0] = 0xa4;
    match_addr1[1] = 0x08;
    match_addr1[2] = 0xea;

    if( (match_addr1[0] ==  addr1[0] && match_addr1[1] ==  addr1[1] && match_addr1[1] ==  addr1[1]))
    {
        bpf_trace_printk("[2021][__sta_info_recalc_tim]::7::peerd[1] %x:%x:%x\\n", addr1[0], addr1[1], addr1[2]);
        bpf_trace_printk("[2021][__sta_info_recalc_tim]::7::peerd[2] %x:%x:%x\\n", addr1[3], addr1[4], addr1[5]);
        bpf_trace_printk("[2021][__sta_info_recalc_tim]::7::peerd[3] aid %d: PS buffer for AC %d \\n", sta->sta.aid, sta->sta.aid);
    }


    
    return 0;
}




int kprobe__ath_tx_complete_buf(struct pt_regs *ctx,struct ath_softc *sc, struct ath_buf *bf)
{
    struct ieee80211_hdr * hdr = (struct ieee80211_hdr *)bf->bf_mpdu->data;
    
    u8 addr1[6],addr2[6];
    bpf_probe_read(&addr1, sizeof(addr1), &hdr->addr1);
    bpf_probe_read(&addr2, sizeof(addr2), &hdr->addr2);





    
    u8 match_addr1[6];

    match_addr1[0] = 0xa4;
    match_addr1[1] = 0x08;
    match_addr1[2] = 0xea;



    if( (match_addr1[0] ==  addr1[0] && match_addr1[1] ==  addr1[1] && match_addr1[1] ==  addr1[1]))
    {
        bpf_trace_printk("[2021][ath_tx_complete_buf]::7::peerd[1] %x:%x:%x\\n", addr1[0], addr1[1], addr1[2]);
        bpf_trace_printk("[2021][ath_tx_complete_buf]::7::peerd[2] %x:%x:%x\\n", addr1[3], addr1[4], addr1[5]);
    }
   

    return 0;
}




int kprobe__ieee80211_rx_napi(struct pt_regs *ctx,struct ieee80211_hw *hw, struct ieee80211_sta *pubsta,
 struct sk_buff *skb, struct napi_struct *napi)
{

  
    struct ieee80211_hdr * hdr = (struct ieee80211_hdr *)skb->data;
    struct ieee80211_hdr * hdr1 = (struct ieee80211_hdr *)skb->data;
    
    
    u8 addr1[6];
    u8 addr2[6];
    u8 match_addr1[6];
    u8 match_addr2[6];
    bpf_probe_read(&addr1, sizeof(addr1), &hdr->addr1);
    bpf_probe_read(&addr2, sizeof(addr2), &hdr->addr2);

   
    match_addr1[0] = 0xa4;
    match_addr1[1] = 0x08;
    match_addr1[2] = 0xea;

    

    if( (match_addr1[0] ==  addr1[0] && match_addr1[1] ==  addr1[1] && match_addr1[1] ==  addr1[1]))
    {
        bpf_trace_printk("[2021][ath10k_process_rx]RECEIVED a [data] packet::2::::7::peerd[1] %x:%x:%x\\n", addr2[0], addr2[1], addr2[2]);
        bpf_trace_printk("[2021][ath10k_process_rx]RECEIVED a [data] packet::2::::7::peerd[2] %x:%x:%x\\n", addr2[3], addr2[4], addr2[5]);



        u16 fc;
        bpf_probe_read(&fc, sizeof(fc), &hdr->frame_control);


        bpf_trace_printk("[2021][ath10k_process_rx]RECEIVED a [data] packet::2::::7::peerd[3] 3::ftype %x ::4::stype %x ::5::PM %x \\n",
           fc & IEEE80211_FCTL_FTYPE, fc & IEEE80211_FCTL_STYPE, fc & IEEE80211_FCTL_PM);
    }

    if( (match_addr1[0] ==  addr2[0] && match_addr1[1] ==  addr2[1] && match_addr1[1] ==  addr2[1]))
    {
        bpf_trace_printk("[2021][ath10k_process_rx]RECEIVED a [data] packet::2::::7::peerd[1] %x:%x:%x\\n", addr2[0], addr2[1], addr2[2]);
        bpf_trace_printk("[2021][ath10k_process_rx]RECEIVED a [data] packet::2::::7::peerd[2] %x:%x:%x\\n", addr2[3], addr2[4], addr2[5]);



        u16 fc;
        bpf_probe_read(&fc, sizeof(fc), &hdr->frame_control);


        bpf_trace_printk("[2021][ath10k_process_rx]RECEIVED a [data] packet::2::::7::peerd[3] 3::ftype %x ::4::stype %x ::5::PM %x \\n",
           fc & IEEE80211_FCTL_FTYPE, fc & IEEE80211_FCTL_STYPE, fc & IEEE80211_FCTL_PM);
    }
    return 0;

}





""")

last=0
print((time.time() * 1000))
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        # (val0, fmt) = msg.split(' ', 1)
        # if (fmt == "Rssi %d, TSF %llu"):
        #     signal = int(val0);
        #     for c in range(0, (100 + signal) / 2):
        # print("*")
        # print((time.time()))
        printb(b"%-18.9f %-18.9f %s" % (time.time(), ts, msg))
        #     print("")
            # if (last != signal):
            #     sound.stop()
            #     sound = pygame.sndarray.make_sound(note[signal])
            #     sound.play(-1)
            # last = signal
    except KeyboardInterrupt:
        exit()
    except ValueError:
        next

sound.stop()