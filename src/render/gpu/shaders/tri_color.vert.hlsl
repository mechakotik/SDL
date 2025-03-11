cbuffer Context : register(b0, space1) {
    float4x4 mvp;
    float4 color;  /* XXX unused */
    float2 texture_size;  /* XXX unused */
};

struct VSInput {
    float2 a_position : POSITION;
    float4 a_color : COLOR0;
};

struct VSOutput {
    float4 v_color : COLOR0;
    float4 gl_Position : SV_POSITION;
};

VSOutput main(VSInput input) {
    VSOutput output;
    output.gl_Position = mul(mvp, float4(input.a_position, 0.0, 1.0));
    output.v_color = input.a_color;
    return output;
}
