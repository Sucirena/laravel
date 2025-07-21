<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class RiwayatPendidikanTenagaAhliResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'id_tenaga_ahli' => $this->id_tenaga_ahli,
            'keterangan' => $this->keterangan,

            'tenaga_ahli' => new TenagaAhliResource($this->whenLoaded('tenagaAhli')),
        ];
    }
}
