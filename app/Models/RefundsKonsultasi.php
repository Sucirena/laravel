<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class RefundsKonsultasi extends Model
{
    use HasFactory;

    protected $table = 'refunds'; // Nama tabel
    protected $fillable = [
        'id_transaksi_konsultasi',
        'refund_amount',
        'refund_status',
        'refund_reason',
    ];

    // Relasi ke model TransaksiKonsultasi
    public function transaksiKonsultasi()
    {
        return $this->belongsTo(TransaksiKonsultasi::class, 'id_transaksi_konsultasi');
    }
}
