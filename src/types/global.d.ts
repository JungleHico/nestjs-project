declare interface ResponseData {
  msg: string;
  data: any;
}

declare interface QueryWithPagination {
  [propName: string]: any;
  current?: number;
  pageSize?: number;
}
