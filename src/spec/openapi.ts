/**
 * OpenAPI 3.x / Swagger 2.x parser
 */

import { readFileSync } from 'fs';
import type { Endpoint, HttpMethod, Parameter, RequestBodySchema, FieldSchema } from '../types.js';

export async function parseOpenApiSpec(specPath: string): Promise<Endpoint[]> {
  let raw: string;

  if (specPath.startsWith('http://') || specPath.startsWith('https://')) {
    const res = await fetch(specPath, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error(`Failed to fetch spec: ${res.status}`);
    raw = await res.text();
  } else {
    raw = readFileSync(specPath, 'utf-8');
  }

  let doc: any;
  if (specPath.endsWith('.yaml') || specPath.endsWith('.yml') || raw.trimStart().startsWith('openapi') || raw.trimStart().startsWith('swagger')) {
    const yaml = await import('yaml');
    doc = yaml.parse(raw);
  } else {
    doc = JSON.parse(raw);
  }

  if (doc.openapi && doc.openapi.startsWith('3')) {
    return parseOpenApi3(doc);
  } else if (doc.swagger && doc.swagger.startsWith('2')) {
    return parseSwagger2(doc);
  }

  throw new Error('Unrecognized spec format. Expected OpenAPI 3.x or Swagger 2.x.');
}

function parseOpenApi3(doc: any): Endpoint[] {
  const endpoints: Endpoint[] = [];
  const paths = doc.paths || {};

  for (const [path, methods] of Object.entries(paths) as [string, any][]) {
    for (const [method, op] of Object.entries(methods) as [string, any][]) {
      if (!isHttpMethod(method)) continue;

      const parameters = extractParameters(op.parameters || []);
      const requestBody = extractRequestBody3(op.requestBody);

      endpoints.push({
        path,
        method: method.toUpperCase() as HttpMethod,
        parameters,
        requestBody,
        description: op.summary || op.description,
      });
    }
  }

  return endpoints;
}

function parseSwagger2(doc: any): Endpoint[] {
  const endpoints: Endpoint[] = [];
  const paths = doc.paths || {};

  for (const [path, methods] of Object.entries(paths) as [string, any][]) {
    for (const [method, op] of Object.entries(methods) as [string, any][]) {
      if (!isHttpMethod(method)) continue;

      const allParams = op.parameters || [];
      const bodyParam = allParams.find((p: any) => p.in === 'body');
      const otherParams = allParams.filter((p: any) => p.in !== 'body');

      const parameters = extractParameters(otherParams);
      const requestBody = bodyParam ? extractSwagger2Body(bodyParam) : undefined;

      endpoints.push({
        path,
        method: method.toUpperCase() as HttpMethod,
        parameters,
        requestBody,
        description: op.summary || op.description,
      });
    }
  }

  return endpoints;
}

function extractParameters(params: any[]): Parameter[] {
  return params.map(p => ({
    name: p.name,
    in: p.in as Parameter['in'],
    type: p.schema?.type || p.type || 'string',
    required: p.required || false,
    example: p.example || p.schema?.example,
  }));
}

function extractRequestBody3(body: any): RequestBodySchema | undefined {
  if (!body?.content) return undefined;

  const jsonContent = body.content['application/json'];
  if (!jsonContent?.schema) return undefined;

  return {
    contentType: 'application/json',
    fields: extractSchemaFields(jsonContent.schema),
  };
}

function extractSwagger2Body(param: any): RequestBodySchema | undefined {
  if (!param.schema) return undefined;
  return {
    contentType: 'application/json',
    fields: extractSchemaFields(param.schema),
  };
}

function extractSchemaFields(schema: any): Record<string, FieldSchema> {
  const fields: Record<string, FieldSchema> = {};
  const props = schema.properties || {};
  const required = new Set(schema.required || []);

  for (const [name, prop] of Object.entries(props) as [string, any][]) {
    fields[name] = {
      type: prop.type || 'string',
      required: required.has(name),
      example: prop.example,
    };
  }

  return fields;
}

const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head']);
function isHttpMethod(m: string): boolean {
  return HTTP_METHODS.has(m.toLowerCase());
}
