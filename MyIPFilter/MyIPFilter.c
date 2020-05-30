#include <mach/mach_types.h>
#include <sys/kernel_types.h>
#include <sys/systm.h>
#include <sys/kpi_mbuf.h>
#include <i386/endian.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/kpi_ipfilter.h>
#include <os/log.h>


#define __FILENAME__ (strrchr_(__FILE__, '/') ? strrchr_(__FILE__, '/') + 1 : __FILE__)

#define log(str, ...) os_log(OS_LOG_DEFAULT, "[%s:%d] " str, __FUNCTION__, __LINE__, ##__VA_ARGS__)

kern_return_t MyIPFilter_start (kmod_info_t * ki, void * d);
kern_return_t MyIPFilter_stop (kmod_info_t * ki, void * d);

enum {
    kMyFiltDirIn,
    kMyFiltDirOut,
    kMyFiltNumDirs
};

static ipfilter_t g_filter_ref;
static boolean_t g_filter_registered = FALSE;
static boolean_t g_filter_detached = FALSE;

static void myipfilter_update_cksum(mbuf_t data)
{
    u_int16_t ip_sum;
    u_int16_t tsum;
    struct tcphdr* tcp;
    struct udphdr* udp;
    
    unsigned char *ptr = (unsigned char*)mbuf_data(data);
    
    struct ip *ip = (struct ip*)ptr;
    if (ip->ip_v != 4)
        return;
    
    ip->ip_sum = 0;
    mbuf_inet_cksum(data, 0, 0, ip->ip_hl << 2, &ip_sum); // ip sum
    
    ip->ip_sum = ip_sum;
    switch (ip->ip_p) {
        case IPPROTO_TCP:
            tcp = (struct tcphdr*)(ptr + (ip->ip_hl << 2));
            tcp->th_sum = 0;
            mbuf_inet_cksum(data, IPPROTO_TCP, ip->ip_hl << 2, ntohs(ip->ip_len) - (ip->ip_hl << 2), &tsum);
            tcp->th_sum = tsum;
            break;
        case IPPROTO_UDP:
            udp = (struct udphdr*)(ptr + (ip->ip_hl << 2));
            udp->uh_sum = 0;
            mbuf_inet_cksum(data, IPPROTO_UDP, ip->ip_hl << 2, ntohs(ip->ip_len) - (ip->ip_hl << 2), &tsum);
            udp->uh_sum = tsum;
            break;
        default:
            break;
    }
    
    mbuf_clear_csum_performed(data); // Needed?
}

static void log_ip_packet(mbuf_t *data, int dir)
{
    char src[32], dst[32];
    struct ip *ip = (struct ip*)mbuf_data(*data);
    
    if (ip->ip_v != 4)
        return;
    
    bzero(src, sizeof(src));
    bzero(dst, sizeof(dst));
    inet_ntop(AF_INET, &ip->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &ip->ip_dst, dst, sizeof(dst));
    
    switch (ip->ip_p) {
        case IPPROTO_TCP:
            log("TCP: ");
            break;
        case IPPROTO_UDP:
            log("UDP: ");
            break;
        case IPPROTO_ICMP:
            log("ICMP: ");
        default:
            log("OTHER: ");
            break;
    }
    
    log("%s -> %s\n", src, dst);
}

// View logs sudo log show --last 5m --predicate "senderImagePath CONTAINS \"MyIPFilter\""

static errno_t myipfilter_output_redirect(void *cookie, mbuf_t *data, ipf_pktopts_t options)
{
    struct in_addr dst_ip;
    struct in_addr source_new;
    int ret;
    
    struct ip *iph = (struct ip*)mbuf_data(*data);
    if (iph->ip_v != 4)
        return 0;
    
    inet_aton("178.62.194.149", &dst_ip);
    inet_aton("192.168.1.41", &source_new);
    
    if (iph->ip_dst.s_addr == dst_ip.s_addr && iph->ip_src.s_addr != source_new.s_addr)
    {
        log("before we modify the src ip\n");
        log_ip_packet(data, kMyFiltDirOut);
        
        mbuf_t new_packet;
        unsigned char packet[1500] = {0};
        errno_t result = 0;
        
        size_t totalLength = (
            mbuf_flags(*data) & MBUF_PKTHDR ?
            mbuf_pkthdr_len(*data) : mbuf_len(*data)
        );
        
        // copy the mbuf to memory
        mbuf_copydata(*data, 0, totalLength, packet);
        mbuf_dup(*data, MBUF_DONTWAIT, &new_packet);
        mbuf_outbound_finalize(new_packet, AF_INET, 0);

        struct ip *ip= (struct ip*)packet;

        // Change the source ip
        ip->ip_src = source_new;
                
        // copy back the modified packet to mbufs
        mbuf_copyback(new_packet, 0, ntohs(ip->ip_len), packet, MBUF_DONTWAIT);

        // update checksum now we've modified the src ip
        myipfilter_update_cksum(new_packet);
        
        log("after changing src ip:\n");
        log_ip_packet(&new_packet, kMyFiltDirOut);
        
        ret = ipf_inject_output(new_packet, g_filter_ref, options);
     return ret == 0 ? EJUSTRETURN : ret;
    }
    return 0;
}

static errno_t myipfilter_output(void *cookie, mbuf_t *data, ipf_pktopts_t options)
{
    if (data)
    {
     
        if(mbuf_len(*data) >= sizeof(struct ip))
            return myipfilter_output_redirect(cookie, data, options);
    }

    return 0;
}

static void myipfilter_detach(void *cookie)
{
    g_filter_detached = TRUE;
}

static struct ipf_filter g_my_ip_filter = { 
    NULL,
    "com.osxkernel.MyIPFilter",
    NULL,
    myipfilter_output,
    myipfilter_detach
};  

kern_return_t MyIPFilter_start (kmod_info_t * ki, void * d) {
    
    int result;
    
    result = ipf_addv4(&g_my_ip_filter, &g_filter_ref);
    
    if (result == KERN_SUCCESS)
        g_filter_registered = TRUE;
    
    return result;
}

kern_return_t MyIPFilter_stop (kmod_info_t * ki, void * d) {
    
    if (g_filter_registered)
    {
        ipf_remove(g_filter_ref);
        g_filter_registered = FALSE;

    }
    /* We need to ensure filter is detached before we return */
    if (!g_filter_detached)
        return EAGAIN; // Try unloading again.
    
    return KERN_SUCCESS;
}
