/*
Author carlos.perez<at>trustedsec.com

Description: LogParser 2.2 query to look for known webshells being used by those exploiting the HAFNIUM vulnerability
             where attempts to access to webshell where succesful. 

Version: 1.0
*/

SELECT date,time,cs-uri-stem,cs-uri-query,c-ip,cs-method,sc-status,cs(user-agent),Logfilename 
FROM '<path to logs>\W3SVC1\*.log'
WHERE ((extract_path(cs-uri-stem) IN ('/owa/auth/15.0.1395';'/owa/auth/15.0.1395/scripts/premium';'/owa/auth/15.0.1395/scripts';
'/owa/auth/15.0.1395/themes/resources';'/owa/auth/15.0.1395/themes';'/owa/auth/current/scripts/premium';'/owa/auth/current/scripts';
'/owa/auth/current/themes/resources';'/owa/auth/current/themes';'/owa/auth/current';'/owa/auth';'/aspnet_client';
'/aspnet_client/system_web';'/ecp')) AND  
(extract_filename(cs-uri-stem) IN ('web.aspx';'help.aspx';'document.aspx';'errorEE.aspx';'errorEEE.aspx';'errorEW.aspx';'errorFF.aspx';
'healthcheck.aspx';'iistart.aspx';'aspnet_www.aspx';'aspnet_client.aspx';'xx.aspx';'shell.aspx';'shellex.aspx';'supp0rt.aspx';
'HttpProxy.aspx';'aspnet_iisstart.aspx';'one.aspx';'t.aspx';'discover.aspx';'aspnettest.aspx';'error.aspx';'MultiUp.aspx';'OutlookEN.aspx';
'logon.aspx';'owa.aspx';'error_ui.aspx';'error2.aspx';'errorfe.aspx';'error.aspx';'logoff.aspx';'signin.aspx';'logout.aspx';'7up.aspx';
'logff.aspx';'errorl.aspx';'errori.aspx';'outlooken.aspx';'outlookch.aspx';'outlookdn.aspx';'Microsoft.aspx';'outlook.aspx';'changepassword.aspx';
'erroref.aspx';'erroree.aspx';'errorff.aspx';'error3.aspx';'error1.aspx';'OutlookCL.aspx';'response.aspx';'error0.aspx';'error4.aspx';
'error5.aspx';'error6.aspx';'login.aspx';'start.aspx';'access.aspx';'log.aspx';'remote.aspx';'admin.aspx';'error7.aspx';'error8.aspx';
'error9.aspx';'iisstart.aspx';'default.aspx';'ice.aspx';'loqon.aspx';'getidtoken.aspx';'gettokenid.aspx';'exppw.aspx';'ExchangeEventLogManager.aspx';
'owaauth.aspx';'exppassword.aspx';'loqoff.aspx';'twofactorauthenticationsignin.aspx';'highshell.aspx';'shell.aspx';'yansoooooooooonf.aspx';
'hypershell.aspx';'highshellserver.aspx';'setub.aspx';'segoeuiregular.aspx';'logon-copy.aspx';'forgot.aspx';'isp.aspx';'stylecss.aspx';'screenshot.aspx';
'exchange.aspx';'sql.aspx';'resetpassword.aspx';'addphonenumber.aspx';'printcalendar.aspx';'registerexternallogin.aspx';'file.aspx';'lgnbotl.aspx';
'poster.aspx';'t.aspx';'error2highshellserverinner.aspx';'back.aspx';'managelogins.aspx';'about.aspx';'warn_png.aspx';'highshellserverinner.aspx';
'owafont.aspx';'getidtokens.aspx';'highshellserverfixed.aspx';'1.aspx';'lap1.aspx';'test.aspx';'simple.aspx';'lockout.aspx';'moduledefintions.aspx';
'managepassword.aspx';'verifyphonenumber.aspx';'register.aspx';'redirecthttp.aspx';'confirm.aspx';'global.aspx';'simpledownload.aspx';'autodiscover.aspx';
'source.aspx';'front.aspx';'module.aspx';'contact.aspx';'globl.aspx';'manage.aspx';'eclipsetheme.aspx';'errorn.aspx';'$rgv2vah.aspx';'mymaster.aspx';
'newimage.aspx';'base.aspx';'owatheme.aspx';'script.aspx';'highshelllocal.aspx';'k2.aspx';'ShellCsDotNet.aspx';'picmaker.aspx';'resetpasswordconfirmation.aspx';
'ctxconfig.aspx';'owafont_ko.aspx';'lgntopr.aspx';'owafont_vi.aspx';'down.aspx';'warn.aspx';'lgntopm.aspx';'office365_cn.aspx';'owafont_zh_cht.aspx';
'template.aspx';'favicon_office.aspx';'OutlookCNLogManagment.aspx';'upload.aspx';'olk_logo_white_small.aspx';'up.aspx';'lgntopl.aspx';'Messages.aspx';
'Hybrid.aspx';'Services.aspx';'Types.aspx';'bin.aspx';'bg_gradient_login.aspx';'olk_logo_white.aspx';'lgnbotr.aspx';'bg_gradient.aspx';'segoeui-regular.aspx';
'lgnleft.aspx';'lgnexlogo.aspx';'segoeui-semilight.aspx';'weberrors.aspx';'owafont_zh_chs.aspx';'olk_logo_white_cropped.aspx';'sign_in_arrow_rtl.aspx';'expire.aspx';
'done.aspx';'owa_text_blue.aspx';'segoeui-semibold.aspx';'upl.aspx';'owafont_ja.aspx';'errorAuth.aspx';'sign_in_arrow.aspx';'lgnbotm.aspx';'icon_settings.aspx';
'icp.aspx';'lgnright.aspx';'web.aspx';'favicon.aspx';'LiveIdErrorE.aspx';'err.aspx';'scripts.aspx';'premium.aspx';'fexppw.aspx';'aria-web-telemetry.aspx';
'flogon.aspx';'owafont_ru.aspx';'themes.aspx';'resources.aspx';'resource.aspx';'current.aspx';'403.aspx';'ExchangeErrorLog.aspx';'errror.aspx';
'aria-webjs-compact-sdk-1.1.0.aspx';'errorr.aspx';'ExchangeInstallError.aspx';'errorfz.aspx';'erroren.aspx';'tuna.aspx';'errorde.aspx';'404.aspx';'2.aspx';
'3.aspx';'4.aspx';'5.aspx';'6.aspx';'7.aspx';'8.aspx';'9.aspx';'10.aspx';'show.aspx';'connect.aspx';'errorFFLog.ashx';'errorlogs.aspx';'Errorowaauth.aspx';
'lgntoml.aspx';'log.ashx';'logerror.aspx';'ok.aspx';'okok.aspx';'auth.ashx';'auth.aspx';'owafont_en.aspx';'owaservice.aspx';'ProxyRedirect.aspx';'redir.aspx';
'resources.jpg.aspx';'sign.aspx';'system_io.aspx';'ui.aspxview.aspx';'ui.aspx';'view.aspx';'OutlookCM.aspx';'ExchangeTemplateManagePages.aspx';'AutodiscoverExchangeManagment.aspx';
'AutodiscoverExchange.aspx';'IndexExchangeManagment.aspx';'outlookapi.aspx';'owaauthE.aspx';'AutodiscoverExchangeLogManager.aspx';'AutodiscoverLogManager.aspx';'LogManager.aspx';
'ExchangeLogManager.aspx';'ExchangeManagment.aspx';'owaExchangeManagment.aspx';'ewsExchangeManagment.aspx';'ecpExchangeManagment.aspx';'rpcExchangeManagment.aspx';
'oabExchangeManagment.aspx';'ExchangeManager.aspx';'errorfb.aspx';'logof.aspx';'owaau.aspx';'errorFS.aspx';'PL8106450.aspx';'conn.aspx';'RedireSuiteidToken.aspx';
'DefaultExchangeServerPage.aspx';'Default.Theme.OWA.aspx';'Sign_in_logos.aspx';'ServerRequirementResources.aspx';'Exch_error.aspx';'Currenttemplate.aspx';'flogen.aspx';
'tems.aspx';'0QWYSEXe.aspx';'0q1iS7mn.aspx';'2XJHwN19.aspx';'8aUco9ZK.aspx';'E3MsTjP8.aspx';'F48zhi6U.aspx';'Fc1b3WDP.aspx';'HttpProxy.aspx';'McYhCzdb.aspx';
'RedirSuiteServerProxy.aspx';'UwSPMsFi.aspx';'aspnet_client.aspx';'aspnettest.aspx';'error_page.aspx';'help.aspx';'iispage.aspx';'load.aspx';'ogu7zFil.aspx';'shellex.aspx';
'sol.aspx';'supp0rt.aspx';'uHSPTWMG.aspx';'web.config.aspx';'zXkZu6bn.aspx';'About.aspx';'OutlookAR.aspx';'OutlookAS.aspx';'OutlookDA.aspx';'OutlookDE.aspx';'OutlookES.aspx';
'OutlookFR.aspx';'OutlookIO.aspx';'OutlookIT.aspx';'OutlookPL.aspx';'OutlookSE.aspx'))) AND sc-status = 200