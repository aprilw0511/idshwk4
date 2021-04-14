@load base/frameworks/sumstats

event http_reply(c: connection, version: string, code: count, reason: string) {
    SumStats::observe("response", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
    if (code == 404) {
        SumStats::observe("response404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
    }
}

event zeek_init() {
    local res_all = SumStats::Reducer($stream="response", $apply=set(SumStats::SUM));
    local res_404 = SumStats::Reducer($stream="response404", $apply=set(SumStats::SUM,SumStats::UNIQUE));
    local res_unique404 = SumStats::Reducer($stream="unique_response404", $apply=set(SumStats::UNIQUE)); 
    SumStats::create([$name="idshwk4", 
                      $epoch=10min, 
                      $reducers=set(res_all, res_404), 
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = 
                       {
                            local r_all = result["response"];
                            local r_404 = result["response404"];
                            local r_unique404 = result["unique_response404"];
                            if (r_404$num > 2 && (r_404$num / r_all$num) > 0.2 ) 
                            {
                                if(r_unique404$unique/r_404$sum>0.5)
                                {
                                     print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, r_404$num, r_404$unique);
                                }
                            } 
                        }
                    ]);
}
