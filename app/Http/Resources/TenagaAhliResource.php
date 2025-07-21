<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class TenagaAhliResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array{
        return [
            'id' => $this->id,
            'nomor_str' => $this->nomor_str,
            'spesialisasi' => $this->spesialisasi,
            'jadwal_aktif' => $this->jadwal_aktif,
            'lokasi_praktik' => $this->lokasi_praktik,
            'biaya_konsultasi' => $this->biaya_konsultasi,
            'tabungan' => $this->tabungan,

            'user' => new UserResource($this->whenLoaded('user')),
            'riwayat_pendidikan' => RiwayatPendidikanTenagaAhliResource::collection($this->riwayatPendidikan),
        ];
    }
}
