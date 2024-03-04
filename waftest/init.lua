require 'config'
require 'lib'

--args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri

--white_ip_check
function white_ip_check()
     if config_white_ip_check == "on" then
        local IP_WHITE_RULE = get_rule('WhiteIp.rule')
        local WHITE_IP = get_client_ip()
        if IP_WHITE_RULE ~= nil then
            for _,rule in pairs(IP_WHITE_RULE) do
                if rule ~= "" and rulematch(WHITE_IP,rule,"jo") then
                    log_record('White_IP',ngx.var_request_uri,"_","_")
                    return true
                end
            end
        end
    end
end

--black_ip_check
function black_ip_check()
     if config_black_ip_check == "on" then
        local IP_BLACK_RULE = get_rule('BlackIp.rule')
        local BLACK_IP = get_client_ip()
        if IP_BLACK_RULE ~= nil then
            for _,rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and rulematch(BLACK_IP,rule,"jo") then
                    log_record('BlackList_IP',ngx.var_request_uri,"_","_")
                    if config_waf_enable == "on" then
                        ngx.exit(403)
                        return true
                    end
                end
            end
        end
    end
end

--white_url_check
function white_url_check()
    if config_white_url_check == "on" then
        local URL_WHITE_RULES = get_rule('WhiteUrl.rule')
        local REQ_URI = ngx.var.request_uri
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and rulematch(REQ_URI,rule,"jo") then
                    return true
                end
            end
        end
    end
end

--cc_attack_check
function cc_attack_check()
    if config_cc_check == "on" then
        local ATTACK_URI=ngx.var.uri
        local CC_TOKEN = get_client_ip()..ATTACK_URI
        local limit = ngx.shared.limit
        CCcount=tonumber(string.match(config_cc_rate,'(.*)/'))
        CCseconds=tonumber(string.match(config_cc_rate,'/(.*)'))
        local req,_ = limit:get(CC_TOKEN)
        if req then
            if req > CCcount then
                log_record('CC_Attack',ngx.var.request_uri,"-","-")
                if config_waf_enable == "on" then
                    ngx.exit(403)
                end
            else
                limit:incr(CC_TOKEN,1)
            end
        else
            limit:set(CC_TOKEN,1,CCseconds)
        end
    end
    return false
end

--cookie_attack_check
function cookie_attack_check()
    if config_cookie_check == "on" then
        local COOKIE_RULES = get_rule('Cookie.rule')
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            for _,rule in pairs(COOKIE_RULES) do
                if rule ~="" and rulematch(USER_COOKIE,rule,"jo") then
                    log_record('Deny_Cookie',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
             end
	 end
    end
    return false
end

--url_attack_check
function url_attack_check()
    if config_url_check == "on" then
        local URL_RULES = get_rule('Url.rule')
        local REQ_URI = ngx.var.request_uri
        for _,rule in pairs(URL_RULES) do
            if rule ~="" and rulematch(REQ_URI,rule,"jo") then
                log_record('Deny_URL',REQ_URI,"-",rule)
                if config_waf_enable == "on" then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--url_args_attack_check
function url_args_attack_check()
    if config_url_args_check == "on" then
        local ARGS_RULES = get_rule('Args.rule')
        for _,rule in pairs(ARGS_RULES) do
            local REQ_ARGS = ngx.req.get_uri_args()
            for key, val in pairs(REQ_ARGS) do
                if type(val) == 'table' then
                    ARGS_DATA = table.concat(val, " ")
                else
                    ARGS_DATA = val
                end
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(ARGS_DATA),rule,"jo") then
                    log_record('Deny_URL_Args',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end
--user_agent_attack_check
function user_agent_attack_check()
    if config_user_agent_check == "on" then
        local USER_AGENT_RULES = get_rule('UserAgent.rule')
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
                if rule ~="" and rulematch(USER_AGENT,rule,"jo") then
                    log_record('Deny_USER_AGENT',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

--post_attack_check
function post_attack_check()
    if config_post_check == "on" then
        local POST_RULES = get_rule('Post.rule')
        local REQUEST_METHOD = ngx.var.request_method
        if REQUEST_METHOD == "POST" then
            for _, rule in pairs(POST_RULES) do
                if rule ~= "" and rulematch(ngx.var.request_uri, rule, "jo") then
                    log_record('Deny_POST', ngx.var.request_uri, "-", rule)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

