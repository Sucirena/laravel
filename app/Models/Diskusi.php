<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

class Diskusi extends Model
{
    use HasFactory;

    protected $table = 'diskusi';

    public $incrementing = false; // Karena menggunakan UUID
    protected $keyType = 'string'; // Tipe data primary key adalah string

    protected $fillable = [
        'id_pasien',
        'judul',
        'isi',
    ];

    // Event untuk membuat UUID secara otomatis saat model dibuat
    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            $model->{$model->getKeyName()} = (string) Str::uuid();
        });
    }

    /**
     * Relasi ke model Pasien (one-to-many, diskusi milik seorang pasien).
     */
    public function pasien()
    {
        return $this->belongsTo(Pasien::class, 'id_pasien');
    }

    /**
     * Relasi ke model GambarDiskusi (one-to-many, diskusi memiliki banyak gambar).
     */
    public function gambarDiskusi()
    {
        return $this->hasMany(GambarDiskusi::class, 'id_diskusi');
    }

    /**
     * Relasi ke model Balasan (one-to-many, diskusi memiliki banyak balasan).
     */
    public function balasan()
    {
        return $this->hasMany(Balasan::class, 'id_diskusi');
    }
}
