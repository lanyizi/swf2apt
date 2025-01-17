﻿using SwfLib.Data;
using SwfLib.Gradients;

namespace SwfLib.Shapes.FillStyles {
    public class RadialGradientFillStyleRGB : FillStyleRGB {

        public SwfMatrix GradientMatrix = SwfMatrix.Identity;

        public GradientRGB Gradient;

        public ushort BitmapID;

        public override FillStyleType Type {
            get { return FillStyleType.RadialGradient; }
        }

        public override TResult AcceptVisitor<TArg, TResult>(IFillStyleRGBVisitor<TArg, TResult> visitor, TArg arg) {
            return visitor.Visit(this, arg);
        }

    }
}
