import * as dotenv from 'dotenv';
dotenv.config();

export const certificate = process.env.CERTIFICATE?.replace(/\\n/g, '\n') ;
export const privateKey = process.env.PRIVATEKEY?.replace(/\\n/g, '\n') ;
export const accessKeyId = process.env.BYTEPLUS_ACCESS_KEY;
export const accessKeySecret = process.env.BYTEPLUS_SECRET_KEY;

const now = new Date();
export const ShortDate = now.toISOString().split('T')[0].replace(/-/g, '');
export const XDate = now.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
