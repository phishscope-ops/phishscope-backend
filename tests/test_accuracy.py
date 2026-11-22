"""Accuracy regressions. Run: python -m unittest discover -s tests -v"""
import unittest
from unittest.mock import patch

import httpx

from app.analysis.normalize import extract_urls
from app.analysis.domain_intel import domain_findings
from app.engine.ml_client import ml_finding
from app.engine.risk import decide, score_findings
from app.engine.threat_types import classify_threat
from app.intel import providers
from app.models import ScanType, Verdict


class AccuracyTests(unittest.TestCase):
    def test_schemeless_free_tld(self):
        self.assertEqual(extract_urls('عرض vodafone-cash-win.tk/claim'), ['vodafone-cash-win.tk/claim'])

    def test_long_tld_not_truncated(self):
        self.assertEqual(extract_urls('winner.example.international/claim'), ['winner.example.international/claim'])

    def test_explicit_url_not_double_counted(self):
        self.assertEqual(extract_urls('افتح https://example.com/login'), ['https://example.com/login'])

    def test_equivalent_repeated_urls_deduplicated(self):
        self.assertEqual(len(extract_urls('http://example.com example.com')), 1)

    def test_path_case_is_preserved(self):
        self.assertEqual(len(extract_urls('https://example.com/A https://example.com/a')), 2)

    def test_otp_and_time_are_not_urls(self):
        self.assertEqual(extract_urls('الساعة 10.30 والكود 123456'), [])

    def test_legit_ml_cannot_cancel_static_evidence(self):
        f = ml_finding({'state':'confirmed','data':{'probability':0.01,'label':'legit','model_version':'test'}})
        self.assertEqual(f['weight'], 0)
        self.assertEqual(score_findings([{'weight':75},f]),75)

    def test_confident_phishing_is_high_risk(self):
        for probability,weight in [(0.79,45),(0.80,60),(0.89,60),(0.95,75)]:
            f=ml_finding({'state':'confirmed','data':{'probability':probability,'label':'phishing','model_version':'test'}})
            self.assertEqual(f['weight'],weight)
            if probability>=0.8:
                self.assertEqual(decide(weight,[f],[])[0],Verdict.HIGH_RISK)

    def test_no_mx_on_website_is_not_a_threat(self):
        self.assertEqual(sum(f['weight'] for f in domain_findings({'has_mx':False},{'age_days':9000})),0)

    def test_confirmed_urlscan_malicious_is_decisive(self):
        f=[{'rule':'TI_URLSCAN_MALICIOUS','weight':30}]
        score=score_findings(f)
        self.assertGreaterEqual(score,80)
        self.assertEqual(decide(score,f,[])[0],Verdict.MALICIOUS)

    def test_conflict_does_not_change_scored_total(self):
        f=[{'rule':'TI_URLSCAN_MALICIOUS','weight':30},{'rule':'ML_PHISHING','weight':60}]
        e=[{'source':'threat_intel','state':'confirmed','verdict':v} for v in ['SAFE','MALICIOUS']]
        score=score_findings(f)
        self.assertEqual(decide(score,f,e)[0],Verdict.MALICIOUS)
        self.assertEqual(sum(a['weight'] for a in f),score)

    def test_ml_phishing_has_a_phishing_label(self):
        self.assertEqual(classify_threat(ScanType.url,Verdict.HIGH_RISK,[{'rule':'ML_PHISHING'}],'http://example.org',{}),'phishing')


class ProviderTests(unittest.IsolatedAsyncioTestCase):
    async def lookup(self, provider, payload, detail=None):
        def handle(request):
            return httpx.Response(200,json=detail if '/result/' in str(request.url) else payload)
        with patch.object(providers,'_from_cache',return_value=None),patch.object(providers,'_to_cache'),patch.object(providers.settings,'urlscan_api_key','test'),patch.object(providers.settings,'urlhaus_auth_key','test'):
            async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
                return await provider(client,None,'https://example.org/')

    async def test_urlhaus_not_listed_is_inconclusive(self):
        r=await self.lookup(providers.check_urlhaus,{'query_status':'no_results'})
        self.assertEqual((r['state'],r['verdict']),('inconclusive',None))

    async def test_urlhaus_positive_is_malicious(self):
        r=await self.lookup(providers.check_urlhaus,{'query_status':'ok','threat':'malware_download'})
        self.assertEqual(r['verdict'],'MALICIOUS')

    async def test_urlhaus_api_error_is_not_safe(self):
        r=await self.lookup(providers.check_urlhaus,{'query_status':'invalid_auth_key'})
        self.assertEqual(r['state'],'unavailable')

    async def test_urlscan_missing_verdict_is_not_safe(self):
        r=await self.lookup(providers.check_urlscan,{'results':[{'_id':'00000000-0000-4000-8000-000000000001'}]}, {})
        self.assertEqual((r['state'],r['verdict']),('inconclusive',None))

    async def test_urlscan_reads_real_result_verdict(self):
        r=await self.lookup(providers.check_urlscan,{'results':[{'_id':'00000000-0000-4000-8000-000000000001'}]}, {'verdicts':{'overall':{'malicious':True,'score':100,'tags':['phishing']}}})
        self.assertEqual(r['verdict'],'MALICIOUS')
        self.assertEqual(r['data']['verdict_source'],'result_api')


if __name__=='__main__':
    unittest.main()
