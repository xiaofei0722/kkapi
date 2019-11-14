#!/user/bin/env python
#coding=utf-8
'''
@project : my_rf
@author  : djcps
#@file   : test_case.py
#@ide    : PyCharm
#@time   : 2019-05-28 12:37:01
'''
#coding=utf-8

import unittest
from ddt import *
from core.readExcel import *
from core.testBase import *
import jsonpath
from core.functions import *
from db_operate.mysql_operate import MySQLOperate
from db_operate.redis_operate import RedisOperate
import requests


@ddt
class Test(unittest.TestCase):

    api_data = read_excel()

    #全局变量池
    saves = {}

    #识别${key}的正则表达式
    EXPR = '\$\{(.*?)\}'
    #识别函数助手
    FUNC_EXPR = '__.*?\(.*?\)'


    def save_date(self,source,key,jexpr):
        '''
        提取参数并保存至全局变量池
        :param source: 目标字符串
        :param key: 全局变量池的key
        :param jexpr: jsonpath表达式
        :return:
        '''
        value = jsonpath.jsonpath(source,jexpr)[0]

        self.saves[key] = value
        logger.info("保存 {}=>{} 到全局变量池".format(key,value))

    def save_header(self,source,key,zzp):
        '''
        提取头部参数并保存至全局变量池
        :param source: 目标字符串
        :param key: 全局变量池的key
        :param jexpr: 正则表达式
        :return:
        '''
        value = re.findall(zzp,source)
        value = "".join(value)
        self.saves[key] = value
        logger.info("保存 {}=>{} 到全局变量池".format(key, value))

    def build_param(self,string):
        '''
        识别${key}并替换成全局变量池的value,处理__func()函数助手
        :param str: 待替换的字符串
        :return:
        '''

        #遍历所有取值并做替换
        keys = re.findall(self.EXPR, string)
        for key in keys:
            value = self.saves.get(key)
            string = string.replace('${'+key+'}',str(value))


        #遍历所有函数助手并执行，结束后替换
        funcs = re.findall(self.FUNC_EXPR, string)
        for func in funcs:
            fuc = func.split('__')[1]
            fuc_name = fuc.split("(")[0]
            fuc = fuc.replace(fuc_name,fuc_name.lower())
            value = eval(fuc)
            string = string.replace(func,str(value))
        return string

    def execute_setup_sql(self,db_connect,setup_sql):
        '''
        执行setup_sql,并保存结果至参数池
        :param db_connect: mysql数据库实例
        :param setup_sql: 前置sql
        :return:
        '''
        for sql in [i for i in setup_sql.split(";") if i != ""]:
            result = db_connect.execute_sql(sql)
            logger.info("执行前置sql====>{}，影响条数:{}".format(sql,result))
            if sql.lower().startswith("select"):
                logger.info("执行前置sql====>{}，获得以下结果集:{}".format(sql,result))
                # 获取所有查询字段，并保存至公共参数池
                for key in result.keys():
                    self.saves[key] = result[key]
                    logger.info("保存 {}=>{} 到全局变量池".format(key, result[key]))

    def execute_teardown_sql(self,db_connect,teardown_sql):
        '''
        执行teardown_sql,并保存结果至参数池
        :param db_connect: mysql数据库实例
        :param teardown_sql: 后置sql
        :return:
        '''
        for sql in [i for i in teardown_sql.split(";") if i != ""]:
            result = db_connect.execute_sql(sql)
            logger.info("执行后置sql====>{}，影响条数:{}".format(sql, result))
            if sql.lower().startswith("select"):
                logger.info("执行后置sql====>{}，获得以下结果集:{}".format(sql, result))
                # 获取所有查询字段，并保存至公共参数池
                for key in result.keys():
                    self.saves[key] = result[key]
                    logger.info("保存 {}=>{} 到全局变量池".format(key, result[key]))

    def execute_redis_get(self,redis_connect,keys):
        '''
        读取redis中key值,并保存结果至参数池
        :param redis_connect: redis实例
        :param keys:
        :return:
        '''
        for key in [key for key in keys.split(";") if key!=""]:
            value = redis_connect.get(key)
            self.saves[key] = value
            logger.info("保存 {}=>{} 到全局变量池".format(key, value))


    @classmethod
    def setUpClass(cls):

        # 实例化测试基类，自带cookie保持
        cls.request = BaseTest()
        # 登录接口获取token
        # data = {"loginType":"","username":"xiaofei02","password":"13154eff38cce7aeccc729d817f2014b","verificationCode":"","execution":"b215435a-7a05-4af9-9b49-7ebd7ede77ed_ZXlKaGJHY2lPaUpJVXpVeE1pSjkuV00zWFJIaWxkUFZLcVNCbkJYUmFsTVU4ek5rMnRUOXowa1VoVnhGK0lQSnNGSXdYNlM4TDFNTHBBcytxOHQ0aG5JYWxjcDdkV1lOQWhQVW0vM2pBTmgwcVhWOGlmQmtsQjFYekpmZml0aU1XTHM1RmlZQWFsMFY4U2JTV1JaM3g4eklkc2lHd2RDSjR5bTR0eUVrZ0ZlUXZxRGFZcWdYSGI0amVYL0l0RkJzZVNmMVZiaGcwTk83bHNqUWczUk9YZ1k1THB6eERlb0lLTEJxcWtLQno3eUI4djEvSisxN1VPd2lDRXZPK1laQ1kzK1F3akhnWVdpRk5Zc0I2MStBRUoxbTlSeFRDOFNaazl0YlBKMGtuMCsweGxBZHo1UE5DTFpCQ09naU9TZHhGalJZcGtoanNiaFhuYnFvcFJQVEpOUkdxS25VTmg1ODRpNVRhcHRnRjBCQ0Nnb2wyLzQ1eXgzV3ppL1gyZHdTcnlUMFJvNlhCNE1hRUY4elBXSmVVQlJJanQyN0UxbjRTcHQwVWV1U1hZUDlqdG9zaUtsVzlPVTNMdUkzYm02eGlZa0Yvbzdrd1Y3S2dqZ3JmWkF2MVRvNEQ0dXBxUHdLb091QjluMGdsYWZWeTdYa1Nva1VmZ3JhL3haWU12RFA3VWhwYU1WVk5TeTEwUFNURWk3bUxPZGsrRTJpRzhzcmhjWlc4RmU4WndpVEtVanVjdU93WENXSUpZck8wYjgxZEZGdHpDT0VEY0JQU0U1MlZXWFFxbTNTUWlUTEZ1eEVqUjVkU2hsWG80NkhaaXJKeE9lZWIyVEhwdVBPUWs2MEYrRzk2ZUNKZXNaVkQvZUZ6UzFKdnU1aFI4OG1aNElyMGJUM3R6K0Rkd3E1WjVOdEFWS05Ic2ZHN0k3ZkdERjBYeGR1TnhmQ3l5Qk9ZRU9LZHZvNWszU3J4V05rUlY5MEJaVkFGMTlHbm1aM1BjbUNtd1c1RzdNVFZoZXVRWnVtVkdTcVBYK01wY0dzKzd0L2ZPeDFVRkN4aHN3dkZOeWUzeUt5QXduRnorQTNPRXZuNDJDVFJUYi82bjQ0L0o4SFJPT1dHb1dtYWg1VVhTeGhQK1EvNEtBQWw4RHQzM1M2U0d1MGl1MkkxR3MxL0wxRHFwWFRvSFZvKzVqY3hXTkZKZytzVmVqNTlyMzJTVnBPWVZPWkNjb2FreTJzTGVoVVFjOUlicjBsTWp0NmpKWlpNK2s0aWhYalMvWWFMYWpBY3dOd1BxYThFNFZKcW1YS010SEZ4WDlVV1F3OUI3RHM0WG9sT3htWFMwV3N3cTVYK1loaXZrYVcxL1NhWllkWWxMNVhEb2lkN2J0TWJqLzBBdDBJQlY3S2JDNndxbUcvcXJDK2hPZWRkTzFOUXlDbWpwNjNvUkhrQ1lKNFV0RzhvS0FwV3ZQSWgwd3plZTR2eTFwRklEazVoYkl0ZzZFN0hDREw5MUVoMm42MlZQeTNiL0pBOVd5aStNWCs3YTFDNkRzN2Y0V2JZZTRteVpmc3A1NXhEd2VYNjNnTUthR2FWZ1o2TmZrelRzNnNZdG5VcklZR2dxUUxKa255MkY4TVhQeWdUSUtXdVo3dk9heitJWGN4Z2lZQzZ1MDI4MWtDeVNvelUydUVUUmdQUDFBa2t2cGZxSXJMSDZRZDRVSjVaUlkzRnYvOEw2ejlrVUVsOFhmQjhuTWRUMzIxNll6YzJVaEVGeWFubE00TGt5elhORXBKT3pIeEZZSGx5YTkxSEVOK2lwc1pDOTlEWkdURFZXVklWT3dMbDNoeHRRTDM0SFA3TjJtNkJ3Mis1N2h0enhMeUJBOUtkNEszVEI4WEM2VGhkalRSQ3NpU3hDaUtTZ1E5SndFdXZBRDVKdFRLbU1rcjBzaHNFQTYvelFMVTRVWW1IYyt4VUdDeUlCZTJ3OWgxWE56MHBNNVR3bE5KTmVtcXd5KzBKR1BteFNrVnE3Kzl2QzVGZ3lDeCtQZmYxY2FsZzFPb1Q4b1pheDBucDVSTDVlaGRRNWhVa0tvZ1gzZUY5QkxYQkFZOVVaSkovWGNiV2U4cU9xL0NvcjJVOVdTUEFDbTdrM1d3ZUpQY0hJcEF3S3RuczVpcm5KUU0xUVdUZngzWVZyaVFKU21oU3dhZjdTMmRMcWZUUVBmWHJ0dzhjSXRpWmlYRUduRFA2UDFjTVRRNGhNR1ZuZkNmNjU2aVNEWC93azNOWVVuRHEzV1hNS3Z2VHdEbjJGc1ZNellsVkpscTYzRUxPakMrYVdSZ3pQcWJrYlpaSGxUZ0xDcCs2Q0JvWHB5N0NTMjdRZi81b1plOEE2NmpZU0FqUU9QMWpyNTU2UTRMUXFDdFhpWjdhMHA0aVg4VzVySDQ0aW9yaEhoZTRjMk5raXJHSHBxTzl5SXVGcGVSblVIaHhnZVJPWlBWRXlER2NKZSt2Um1sVWZIeGpkQ2JwSmtuRmNKaEJHMzZINzJNTkZtb2ZFR25DdWk1YmJETno0TlVYZzVtNGhNVE1PMDErQjAzd1dPU0JSOEZtR1V1a2N6dTZMMk1udUtKb3RuNzRTT1JWZUkxbERoQUJRQmRkVCtwZUVOeXNrOTJIcUllZDEzOVZxNjNadlF4R01tbHE5WFNtZDhDSmlMNWo3YUxDK0FrMVNvWkJZRTFGTVFOM1YwQnhGVGlZRlFYVUhOL0xXZGZQZGQrRXA2RWplUFlHblM3OWVUNjNPUXdZV0JFV2NxZzJzcXJ4UnBrUktVb2locFRxY3Z4K2wwYXF0TVRvN2RLQ2w2OUFlYk4xZjdiVzR2d0dmTEdDZ1NmQXNOMjJxaU1wdHJjS3VqcEpMcXlRSW55YWRTdWpEbmlzb3h4VTgzbVRsV05JMGxyVkhkcDBkeWo3ajQ5M3oyLzVGblJaVHZ3YVErWTBRUkNKUWZZVVhSR0ZHZnBnM2QyZWNTbHlpYTFxOWNpSEFlYzVtR1NwTkVPd2YwQXdUbXp4aVl4anF6cmlZVnIxd1ZpZ3V5V0MrVHBCOTVuaUsxQ2VmK1QzOWg4OENCSEdxd3NWVXhHbTlqT2hVWFFPOUlkdDNVWCtkQW9RY2tWYUNOVmVsQy90bFdWbmkxcFZVcXY5OE55dmlZZlR1REdjM05CWUhIVk1iNitNSVp2NXhXTXE4YmtQSG5GM0N2aTNYeDRzWkhmU25ZWVB1UFpCTjlPRGtxV202dFRadVZoTW14c2FUQldWZzlwdE1LZjcvQTJ1R0pvQ01YZ0Noa0N2VlB2VTlKSzB4endvbmxEZzdrelNtY1pCVW9GVHN0czY0RThOUjRQcmY5RndyMXRKa1BDRWFnL0hadTNUZVB6T1pHNnRnVys4VEUvVzNzR21iSzVDS0djVjNydmxScjhSQ2JGLzBOdHNKd29Cb1BsVmhjLzR3Nk41anU5eGRBYlg0SGZQdkw0emszVU1tTGpBeDFvTGQxdm5VK3djMllvc1RtemdNeWhLV0FMK3d6Q0hxM1RvNm5qUzJHMEhDYy9zUFEyNnJ5NEt2M1JDNlRBdXFNcGFOSlF0a0JZbzBldmVtTU5uM0pwc3VHMFBKVnFkZ0RMb0sxb3RzMEZsem5TaWk2YmVmcWdoREJTTW5kQXFFNGtNNUxJei9uRkhnTDhZMHpMRmErUTllNFdOaTBvdGoxYXo5WGd0WHJCKzFCbGtXZHJ5U1JTUUNQMVhjZng4Vi9say8xRUFkRmFpZVZ1QmRCSTlGcjdJN0E5eE4zY1BFd2IvZ3cxeHN5U1lHYm90T1RCSkFWd0pYc3dXdHdzM0FXaDZJaktiUW84QWUycXFQWE5RbVVnZjY1aXJpWEpXMU9lL2gzVjdiZzU5R0tIMFVUbngyNXNwKzRkaXdCQVhpbUdJNHFYTWJqQUZkWFhqZFJaNmRIYy9QbEI4SDJBZUt2c1djZjA1TzVyTHc5ZU5qMjNLcHpCdFhmZXZPWmNZM3pLRWFHQjA3ZmJ6TzZBajBQL2IwNFdsK09aZTB3N0w3bWhYREo1Zi9RWVBGcHVMS1JTWFlWTG1SWFFtVDQxUWU1ZmgrMG1TUDFUWWw3K0hnRGxkNWtoMVk5NHRMUFhrclhrQ3ZENFo0YU0zWTVUYjByTEVTZW4vTWZheHlZcFNaWU10M2NFK25xTkQyeVF3ajVIbE41Z1hQcnlxdHBqajNWUDN1djY5OS9XSUNxdStiQUNYREcwSUJCQ01QVkZPeEgzeFFmYkVUcFIvVnNJelA5aEk1MnBSNDJnRSt3M0kudmlEZGp0NnNnVmlETkUtSC1mcVZJeGhNUTJUM2tBejJ1dEJnUTRSM2FKSXBEallvbUVQQUxrcWlyei1Cai1raUxXbmtiYWFib3NCSVNycURBd3NMaEE=","_eventId":"submit","geolocation":""}
        # headers = {"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8","Referer":"https://m8-cas-tenant-m8cmp-sdp.tongfuyun-test.com/cas/login?service=http%3A%2F%2Fconsole.coo.tongfuyun-test.com%2Fcas%2Fvalidate&sn=/","Accept-Language":"zh-CN,zh;q=0.9","Origin":"https://m8-cas-tenant-m8cmp-sdp.tongfuyun-test.com","Upgrade-Insecure-Requests":"1","Content-Type":"application/x-www-form-urlencoded","Cache-Control":"max-age=0","Accept-Encoding":"gzip, deflate, br","User-Agent":"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36"}
        # url = "https://m8-cas-tenant-m8cmp-sdp.tongfuyun-test.com/cas/login?service=http%3A%2F%2Fconsole.coo.tongfuyun-test.com%2Fcas%2Fvalidate&sn=/"
        # request = requests.Session()
        # res = request.post(url=url, headers=headers, params=data, verify=False)
        # resheaders = str(res.headers)
        # cls.token = re.findall('CcsyunPortalToken=(.*?), paas', resheaders)
        # cls.token = {"Authorization":"Bearer "+cls.token[0]}


    @classmethod
    def tearDownClass(cls):
        pass

    @data(*api_data)
    @unpack
    def test_(self,descrption,url,method,headers,cookies,params,body,file,verifytype,verify,saves_headers,saves,dbtype,db,setup_sql,teardown_sql):
        logger.info("用例描述====>"+descrption)
        # headers = json.loads(headers)
        # headers.update(self.token)
        # headers = json.dumps(headers)
        url = self.build_param(url)
        headers = self.build_param(headers)
        params = self.build_param(params)
        body = self.build_param(body)
        setup_sql = self.build_param(setup_sql)
        teardown_sql = self.build_param(teardown_sql)

        params = eval(params) if params else params
        headers = eval(headers) if headers else headers
        cookies = eval(cookies) if cookies else cookies
        body = eval(body) if body else body
        file = eval(file) if file else file

        db_connect = None
        redis_db_connect = None
        res = None
        # 判断数据库类型,暂时只有mysql,redis
        if dbtype.lower() == "mysql":
            db_connect = MySQLOperate(db)
        elif dbtype.lower() == "redis":
            redis_db_connect = RedisOperate(db)
        else:
            pass

        if db_connect:
            self.execute_setup_sql(db_connect,setup_sql)
        if redis_db_connect:
            # 执行teardown_redis操作
            self.execute_redis_get(redis_db_connect,setup_sql)

        # 判断接口请求类型
        if method.upper() == 'GET':
            res = self.request.get_request(url=url,params=params,headers=headers,cookies=cookies)
        elif method.upper() == 'POST':
            res = self.request.post_request(url=url,headers=headers,cookies=cookies,params=params,json=body)
        if method.upper() == 'UPLOAD':
            res = self.request.upload_request(url=url,headers=headers,cookies=cookies,params=params,data=body,files=file)
        else:
            #待扩充，如PUT,DELETE方法
            pass
        if saves:
            # 遍历saves
            for save in saves.split(";"):
                # 切割字符串 如 key=$.data
                key = save.split("=")[0]
                jsp = save.split("=")[1]
                self.save_date(res.json(), key, jsp)
        if saves_headers:
            for saveh in saves_headers.split(";"):
                key = saveh.split("=")[0]
                zzp = saveh.split("=",1)[1]
                self.save_header(str(res.headers),key,zzp)

        if verify:
            # 遍历verify:
            for ver in verify.split(";"):
                expr = ver.split("=")[0]
                exprv = ver.split("=")[1]
                # 判断Jsonpath还是正则断言
                if exprv.startswith("$."):
                    try:
                        actual = jsonpath.jsonpath(res.json(), exprv)
                    except Exception as e:
                        logger.error("接口请求异常,原因：{}".format(e))
                        raise e
                    if isinstance(actual,list):
                        actual = "".join(actual)



                else:
                    actual = re.findall(exprv,res.text)
                    if isinstance(actual, list):
                        actual = "".join(actual)



                if verifytype == '相等':
                    self.request.assertEquals(actual, expr)
                else:
                    self.request.assertIn(expr,actual)

        if db_connect:
            # 执行teardown_sql
            self.execute_teardown_sql(db_connect,teardown_sql)

        if redis_db_connect:
            # 执行teardown_redis操作
            self.execute_redis_get(redis_db_connect,teardown_sql)

        #最后关闭mysql数据库连接
        if db_connect:
            db_connect.db.close()



