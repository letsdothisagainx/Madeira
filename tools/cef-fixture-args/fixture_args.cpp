/* SPDX-License-Identifier: MIT */
#include "fixture_args.h"
#include "steam_cef_policy.h"
namespace madeira_cef_fixture {
int browser_args(const U16 *image,Size image_length,const U16 *line,Size length,
                 bool jitless,U16 *out,Size capacity,U32 cdp_port){
    if(!line||!out||length>32766||!madeira_cef_image(image,image_length)||
       madeira_cef_process_role(line,length)!=MADEIRA_CEF_BROWSER)return -1;
    /* Literal source policy: process_ios.c Steam branch, NOT the Social Club
     * sc_browser_cmdline routine. BRP and every existing Valve flag survive. */
    static constexpr char fixed[]=" --single-process --enable-logging --v=1 --log-severity=verbose"
        " --no-proxy-server --winhttp-proxy-resolver";
    static constexpr char js[]=" --js-flags=--jitless";
    static constexpr char key[]="--disable-features=";
    static constexpr char features[]=",SegmentationPlatform,OptimizationTargetPrediction,OptimizationHints";
    U16 inspector[100];Size inspector_size=0;
    if(cdp_port>=1024&&cdp_port<=65535){
        static constexpr char prefix[]=" --remote-debugging-address=127.0.0.1 --remote-debugging-port=";
        for(Size k=0;k<sizeof(prefix)-1;++k)inspector[inspector_size++]=U16(prefix[k]);
        char digits[5];Size count=0;do{digits[count++]=char('0'+cdp_port%10);cdp_port/=10;}while(cdp_port);
        while(count)inspector[inspector_size++]=U16(digits[--count]);
    }
    Size at=length;bool found=false;
    for(Size p=0;p+sizeof(key)-1<=length;++p){
        Size k=0;while(k<sizeof(key)-1&&line[p+k]==U16(key[k]))++k;
        if(k==sizeof(key)-1){at=p+k;while(at<length&&line[at]!=' '&&line[at]!='"')++at;found=true;break;}
    }
    Size needed=length+(sizeof(fixed)-1)+(jitless?sizeof(js)-1:0)+(found?sizeof(features)-1:0)+inspector_size;
    if(needed>32766||capacity<=needed)return -1;
    Size n=0;for(Size i=0;i<length;++i){
        if(found&&i==at)for(Size j=0;j<sizeof(features)-1;++j)out[n++]=U16(features[j]);
        out[n++]=line[i];
    }
    if(found&&at==length)for(Size j=0;j<sizeof(features)-1;++j)out[n++]=U16(features[j]);
    for(Size j=0;j<sizeof(fixed)-1;++j)out[n++]=U16(fixed[j]);
    if(jitless)for(Size j=0;j<sizeof(js)-1;++j)out[n++]=U16(js[j]);
    for(Size k=0;k<inspector_size;++k)out[n++]=inspector[k];
    out[n]=0;return int(n);
}
}
