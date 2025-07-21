<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

class PercakapanChatbot extends Model
{
    use HasFactory;

    protected $table = 'percakapan_chatbot';

    public $incrementing = false; // Karena menggunakan UUID
    protected $keyType = 'string'; // Tipe data primary key adalah string

    protected $fillable = [
        'id_pasien',
        'label',
        'last_activity',
        'status',
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
     * Relasi ke model PesanChatbot (One-to-Many)
     */
    public function pesanChatbot()
    {
        return $this->hasMany(PesanChatbot::class, 'id_percakapan_chatbot')->orderBy('created_at', 'desc');
    }

    /**
     * Relasi ke model Pasien (Many-to-One)
     */
    public function pasien()
    {
        return $this->belongsTo(Pasien::class, 'id_pasien');
    }
}
