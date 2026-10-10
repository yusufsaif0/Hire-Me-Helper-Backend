import { Controller, Get } from '@nestjs/common';
import { ApiOkResponse, ApiProperty, ApiTags } from '@nestjs/swagger';
import { healthResponseSchemaFor, type HealthResponse } from './lib/contracts';
import { serviceId } from './environment';
class HealthDto implements HealthResponse {
  @ApiProperty({ enum: ['ok'] }) status!: 'ok';
  @ApiProperty({ type: String, enum: [serviceId] }) service!: typeof serviceId;
  @ApiProperty({ enum: ['0.1.0'] }) version!: '0.1.0';
  @ApiProperty({ enum: [0] }) phase!: 0;
  @ApiProperty({ enum: ['mock'] }) integrations!: 'mock';
  @ApiProperty({ format: 'date-time' }) timestamp!: string;
}
@ApiTags('System')
@Controller('health')
export class HealthController {
  @Get()
  @ApiOkResponse({
    type: HealthDto,
    description:
      'Process liveness only. Integrations are mocked; this is not a production readiness check.',
  })
  health(): HealthResponse {
    return healthResponseSchemaFor(serviceId).parse({
      status: 'ok',
      service: serviceId,
      version: '0.1.0',
      phase: 0,
      integrations: 'mock',
      timestamp: new Date().toISOString(),
    });
  }
}
