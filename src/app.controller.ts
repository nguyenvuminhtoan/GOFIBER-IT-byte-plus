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
}
