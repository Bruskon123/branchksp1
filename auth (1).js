import { authGet, authPost, authDelete } from '../_lib/auth.js';
export const onRequestGet = authGet;
export const onRequestPost = authPost;
export const onRequestDelete = authDelete;
