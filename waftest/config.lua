--WAF config file,enable = "on",disable = "off"

--waf I/O
config_waf_enable = "on"
--log dir_path
config_log_dir = "/tmp"
--rule path
config_rule_dir = "/usr/local/openresty/nginx/conf/waftest/rule"
--white url
config_white_url_check = "on"
--white ip
config_white_ip_check = "on"
--black ip
config_black_ip_check = "on"
--url
config_url_check = "on"
--url args
config_url_args_check = "on"
--user agent
config_user_agent_check = "on"
--cookie
config_cookie_check = "on"
--cc
config_cc_check = "on"
--cc rate
config_cc_rate = "10/60"
--post
config_post_check = "on"
--waf output
config_waf_output = "html"
--redirect html
config_waf_redirect_url = "https://8.130.139.21/a"
config_output_html=[[
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Content-Language" content="zh-cn" />
<title>Web应用防火墙</title>
</head>
<body>
<h1 align="center"> 禁止未经允许的渗透测试行为，你的行为已经被记录，我司保留报案起诉权力！
</body>
</html>
]]

