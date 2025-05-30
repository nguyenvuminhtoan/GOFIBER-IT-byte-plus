import { Controller, Get } from '@nestjs/common';
import * as CryptoJS from 'crypto-js';
import axios from 'axios';
import {
  accessKeyId,
  accessKeySecret,
  certificate,
  privateKey,
  ShortDate,
  XDate,
} from './utils';

@Controller()
export class AppController {
  @Get()
  async Login(): Promise<any> {
    const payload = JSON.stringify({
      domain: 'www.example.com',
      public_key: certificate,
      private_key: privateKey,
      repeatable: true,
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'UploadCertificate',
      Version: '2021-06-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:open.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/certificate_service/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );
    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('certificate_service', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);

    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://open.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'certificate_service',
          Region: 'ap-singapore-1',
        },
      },
    );

    return response.data;
  }

  // Phải đăng kí tài khoản tiền mới xài đc
  @Get('/describe-templates')
  async DescribeTemplates(): Promise<any> {
    const payload = JSON.stringify({
      Filters: [
        {
          Name: 'Title',
          Fuzzy: false,
          Value: ['NetTVWeb001', 'NetTV003'],
        },
        {
          Name: 'Id',
          Fuzzy: false,
          Value: ['tpl-sZRpwq', 'tpl-sWm5EW'],
        },
        {
          Name: 'Domain',
          Fuzzy: true,
          Value: ['example.com'],
        },
        {
          Name: 'Type',
          Fuzzy: false,
          Value: ['cipher', 'service'],
        },
        {
          Name: 'Status',
          Fuzzy: false,
          Value: ['locked', 'editing'],
        },
      ],
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'DescribeTemplates',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);

    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  // Phải đăng kí tài khoản tiền mới xài đc
  @Get('/add-template-domain')
  async AddTemplateDomain(): Promise<any> {
    const payload = JSON.stringify({
      Domain: 'www.example.com',
      CipherTemplateId: 'tpl-cqgRvW',
      HTTPSSwitch: 'on',
      ServiceRegion: 'outside_chinese_mainland',
      ServiceTemplateId: 'tpl-s2Q4mq',
      CertId: 'cert-044833503b2349b4b42c2e80b0aa8c23',
      Tags: [
        {
          Key: 'myKey1',
          Value: 'myValue1',
        },
        {
          Key: 'myKey2',
          Value: 'myValue2',
        },
      ],
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'UpdateTemplateDomain',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);

    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/update-template-domain')
  async UpdateTemplateDomain(): Promise<any> {
    const payload = JSON.stringify({
      Domain: 'www.example.com',
      CipherTemplateId: 'tpl-cqgRvW',
      HTTPSSwitch: 'on',
      ServiceRegion: 'outside_chinese_mainland',
      ServiceTemplateId: 'tpl-s2Q4mq',
      CertId: 'cert-044833503b2349b4b42c2e80b0aa8c23',
      Tags: [
        {
          Key: 'myKey1',
          Value: 'myValue1',
        },
        {
          Key: 'myKey2',
          Value: 'myValue2',
        },
      ],
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'AddTemplateDomain',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);

    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/duplicate-template')
  async DuplicateTemplate(): Promise<any> {
    const payload = JSON.stringify({
      ReferredTemplateId: 'tpl-sZRpwq',
      Title: 'Dup_Policy',
      Message: 'This is a dup policy.',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'DuplicateTemplate',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);

    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/update-service-template')
  async UpdateServiceTemplate(): Promise<any> {
    const payload = JSON.stringify({
      TemplateId: 'tpl-sZOlrW',
      Title: 'NewTitle',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'UpdateServiceTemplate',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);

    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/update-cipher-template')
  async UpdateCipherTemplate(): Promise<any> {
    const payload = JSON.stringify({
      TemplateId: 'tpl-c2vy7q',
      TemplateVersion: 'draft',
      HTTPS: {
        DisableHttp: false,
        ForcedRedirect: {
          EnableForcedRedirect: true,
          StatusCode: '302',
        },
        HTTP2: true,
        Hsts: {
          Subdomain: 'include',
          Switch: true,
          Ttl: 1800,
        },
        OCSP: true,
        TlsVersion: ['tlsv1.2', 'tlsv1.3'],
      },
      HttpForcedRedirect: {
        EnableForcedRedirect: false,
        StatusCode: '302',
      },
      Quic: {
        Switch: true,
      },
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'UpdateCipherTemplate',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);

    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/lock-template')
  async LockTemplate(): Promise<any> {
    const payload = JSON.stringify({
      TemplateId: 'tpl-s2N4rW',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'LockTemplate',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);

    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/update-template-domain-name')
  async UpdateTemplateDomainName(): Promise<any> {
    const payload = JSON.stringify({
      Domains: ['www.example.com'],
      CipherTemplateId: 'tpl-cqgRvW',
      HTTPSSwitch: 'on',
      ServiceRegion: 'outside_chinese_mainland',
      ServiceTemplateId: 'tpl-s2Q4mq',
      CertId: 'cert-044833503b2345b4b42c2e81z0aa5c23',
      SparrowRules: [
        {
          Condition: {
            ConditionRule: [
              {
                Object: 'filetype',
                Operator: 'match',
                Type: 'url',
                Value: 'asp;php;jsp;ashx;aspx;do',
              },
            ],
            Connective: 'OR',
          },
          SparrowAction: {
            Action: 'bypass',
            IgnoreCase: true,
            SparrowID: '96ec5429956c42f79a717a4649f3d455',
          },
        },
      ],
      SparrowSwitch: 'on',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'UpdateTemplateDomain',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);

    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  //  Lỗi bên BytePlus
  @Get('/create-function')
  async CreateFunction(): Promise<any> {
    const payload = JSON.stringify({
      Name: 'test-Function',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'CreateFunction',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/full-publish')
  async FullPublish(): Promise<any> {
    const payload = JSON.stringify({
      FunctionId: '3246574',
      Description: 'test publish',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'FullPublish',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/canary-publish')
  async CanaryPublish(): Promise<any> {
    const payload = JSON.stringify({
      FunctionId: '3gyz993****',
      Description: 'test publish',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'CanaryPublish',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/function-bind-domains')
  async FunctionBindDomains(): Promise<any> {
    const payload = JSON.stringify({
      FunctionId: 'b21f19d28c7f4fbbb8b8bc799f28****',
      Domains: ['a.example.com', 'b.example.com'],
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'FunctionBindDomains',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  //Chạy được
  @Get('/create-kv-namespace')
  async CreateKvNamespace(): Promise<any> {
    const payload = JSON.stringify({
      Namespace: 'test-kv1',
      Description: 'test',
      ProjectName: 'default',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'CreateKvNamespace',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/create-key-value')
  async CreateKeyValue(): Promise<any> {
    const payload = JSON.stringify({
      Namespace: 'test-kv1',
      NamespaceId: '46d79a9944ae2fd81f2643e2fe5ef42d****',
      Key: 'testkey',
      Value: 'dGVzdHZhbHVlMTIz',
      TTL: 0,
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'CreateKeyValue',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/submit-refresh-task')
  async SubmitRefreshTask(): Promise<any> {
    const payload = JSON.stringify({
      Type: 'file',
      Urls: 'https://www.example.com/1.txt\nhttps://www.example.com/2.txt',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'SubmitRefreshTask',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/submit-preload-task')
  async SubmitPreloadTask(): Promise<any> {
    const payload = JSON.stringify({
      Urls: 'https://www.example.com/1.txt\nhttps://www.example.com/2.txt',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'SubmitPreloadTask',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/create-service-template')
  async CreateServiceTemplate(): Promise<any> {
    const payload = JSON.stringify({
      Title: 'TestPolicy',
      Message: 'This is a test.',
      Project: 'default',
      OriginProtocol: 'http',
      Origin: [
        {
          Condition: null,
          OriginAction: {
            OriginLines: [
              {
                Address: '1.1.1.1',
                HttpPort: '80',
                HttpsPort: '443',
                InstanceType: 'ip',
                OriginType: 'primary',
                PrivateBucketAccess: false,
                Weight: '1',
                OriginHost: 'abc.example.com',
              },
            ],
          },
        },
      ],
      OriginHost: 'www.example.com',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'CreateServiceTemplate',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/describe-service-template')
  async DescribeServiceTemplate(): Promise<any> {
    const payload = JSON.stringify({
      TemplateId: 'tpl-sZRpwq',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'DescribeServiceTemplate',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/describe-cipher-template')
  async DescribeCipherTemplate(): Promise<any> {
    const payload = JSON.stringify({
      TemplateId: 'tpl-sZRpwq',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'DescribeCipherTemplate',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/describe-template-domains')
  async DescribeTemplateDomains(): Promise<any> {
    const payload = JSON.stringify({
      Filters: [
        {
          Name: 'Domain',
          Value: ['example'],
          Fuzzy: true,
        },
        {
          Name: 'TemplateTitle',
          Value: ['NetTVPlayer'],
          Fuzzy: true,
        },
        {
          Name: 'TemplateId',
          Value: ['tpl-s2DVaW'],
          Fuzzy: false,
        },
        {
          Name: 'TemplateType',
          Value: ['service', 'cipher'],
          Fuzzy: false,
        },
        {
          Name: 'HTTPSSwitch',
          Value: ['off'],
          Fuzzy: false,
        },
        {
          Name: 'WAFStatus',
          Value: ['off'],
        },
        {
          Name: 'Status',
          Value: ['online'],
          Fuzzy: false,
        },
      ],
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'DescribeTemplateDomains',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/start-cdn-domain')
  async StartCdnDomain(): Promise<any> {
    const payload = JSON.stringify({
      Domain: 'www.example.com',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'StartCdnDomain',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/stop-cdn-domain')
  async StopCdnDomain(): Promise<any> {
    const payload = JSON.stringify({
      Domain: 'www.example.com',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'StopCdnDomain',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/delete-cdn-domain')
  async DeleteCdnDomain(): Promise<any> {
    const payload = JSON.stringify({
      Domain: 'www.example.com',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'DeleteCdnDomain',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/add-certificate')
  async AddCertificate(): Promise<any> {
    const payload = JSON.stringify({
      Domain: 'www.example.com',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'AddCertificate',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/list-certInfo')
  async ListCertInfo(): Promise<any> {
    const payload = JSON.stringify({
      Domain: 'www.example.com',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'ListCertInfo',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/list-cdn-cert-info')
  async ListCdnCertInfo(): Promise<any> {
    const payload = JSON.stringify({
      Domain: 'www.example.com',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'ListCdnCertInfo',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/describe-cert-config')
  async DescribeCertConfig(): Promise<any> {
    const payload = JSON.stringify({
      Domain: 'www.example.com',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'DescribeCertConfig',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }

  @Get('/describe-edge-status-code-ranking')
  async DescribeEdgeStatusCodeRanking(): Promise<any> {
    const payload = JSON.stringify({
      StartTime: 1710259200,
      EndTime: 1710835599,
      Metric: 'status_2xx',
      Item: 'domain',
      Project: 'my_project',
      Domain: 'www.example.com,www.test.com,img.example.com',
    });

    const payloadHash = CryptoJS.SHA256(payload).toString(CryptoJS.enc.Hex);

    const queryParams = {
      Action: 'DescribeEdgeStatusCodeRanking',
      Version: '2021-03-01',
    };

    const CanonicalQueryString = Object.keys(queryParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`,
      )
      .join('&');

    const SignedHeaders = 'content-type;host;x-content-sha256;x-date';

    const CanonicalHeaders =
      [
        `content-type:application/json`,
        'host:cdn.byteplusapi.com',
        `x-content-sha256:${payloadHash}`,
        `x-date:${XDate}`,
      ].join('\n') + '\n';

    const credentialScope = `${ShortDate}/ap-singapore-1/cdn/request`;

    const CanonicalRequest =
      'POST' +
      '\n' +
      '/' +
      '\n' +
      CanonicalQueryString +
      '\n' +
      CanonicalHeaders +
      '\n' +
      SignedHeaders +
      '\n' +
      payloadHash;

    const hashedCanonicalRequest = CryptoJS.SHA256(CanonicalRequest).toString(
      CryptoJS.enc.Hex,
    );

    const StringToSign =
      'HMAC-SHA256' +
      '\n' +
      XDate +
      '\n' +
      credentialScope +
      '\n' +
      hashedCanonicalRequest;

    const kSecret = accessKeySecret;
    const kDate = CryptoJS.HmacSHA256(ShortDate, kSecret);
    const kRegion = CryptoJS.HmacSHA256('ap-singapore-1', kDate);
    const kService = CryptoJS.HmacSHA256('cdn', kRegion);
    const kSigning = CryptoJS.HmacSHA256('request', kService);
    const signature = CryptoJS.HmacSHA256(StringToSign, kSigning).toString(
      CryptoJS.enc.Hex,
    );

    const response = await axios.post(
      `https://cdn.byteplusapi.com/?${CanonicalQueryString}`,
      payload,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Date': XDate,
          'x-content-sha256': payloadHash,
          'X-Signature-Version': '2',
          Authorization: `HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${SignedHeaders}, Signature=${signature}`,
          ServiceName: 'cdn',
          Region: 'ap-singapore-1',
          Host: 'cdn.byteplusapi.com',
        },
      },
    );

    return response.data;
  }
  
}
